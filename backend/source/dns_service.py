"""Single-instance supervisor for loopback-only scoped Claude DNS.

Only the supervisor's exact child is restarted. No DNS/proxy policy fallback.
The existing login launch command remains valid.
"""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes as W
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent
DNS = ROOT / 'dns'


def physical_root():
    if ROOT.resolve() != ROOT.absolute() or DNS.resolve() != DNS.absolute():
        raise RuntimeError('redirected_service_root')


def atomic_state(name, value):
    if name not in ('process.json', 'supervisor.json'):
        raise ValueError('unknown_state_file')
    physical_root()
    value = dict(value, at=dt.datetime.now(dt.timezone.utc).isoformat())
    temp = DNS / ('.' + name + '.' + str(os.getpid()) + '.tmp')
    temp.write_text(json.dumps(value), encoding='utf-8')
    os.replace(temp, DNS / name)


def log_state(status, **values):
    # Fixed lifecycle values only. Never DNS names, answers, or credentials.
    path = DNS / 'supervisor.log'
    if path.exists() and path.stat().st_size > 1048576:
        os.replace(path, DNS / 'supervisor.previous.log')
    with path.open('a', encoding='utf-8') as log:
        log.write(json.dumps(dict(status=status, at=dt.datetime.now(dt.timezone.utc).isoformat(), **values)) + '\n')


class SingleInstance:
    def __init__(self):
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, W.BOOL, W.LPCWSTR]
        kernel.CreateMutexW.restype = W.HANDLE
        kernel.CloseHandle.argtypes = [W.HANDLE]
        self.kernel = kernel
        name = 'Local\\ClaudeScopedDNS-' + hashlib.sha256(str(ROOT).casefold().encode()).hexdigest()[:20]
        self.handle = kernel.CreateMutexW(None, False, name)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        self.acquired = ctypes.get_last_error() != 183

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class OwnedWorkerJob:
    """Unnamed job: supervisor exit closes only its own attached worker."""
    def __init__(self):
        class Basic(ctypes.Structure):
            _fields_ = [('processTime', ctypes.c_longlong), ('jobTime', ctypes.c_longlong),
                        ('flags', W.DWORD), ('minWork', ctypes.c_size_t), ('maxWork', ctypes.c_size_t),
                        ('activeLimit', W.DWORD), ('affinity', ctypes.c_size_t),
                        ('priority', W.DWORD), ('scheduling', W.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ('readOps', 'writeOps', 'otherOps', 'readBytes', 'writeBytes', 'otherBytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('basic', Basic), ('io', IO), ('processMemory', ctypes.c_size_t),
                        ('jobMemory', ctypes.c_size_t), ('peakProcessMemory', ctypes.c_size_t),
                        ('peakJobMemory', ctypes.c_size_t)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, W.LPCWSTR]
        kernel.CreateJobObjectW.restype = W.HANDLE
        kernel.SetInformationJobObject.argtypes = [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD]
        kernel.AssignProcessToJobObject.argtypes = [W.HANDLE, W.HANDLE]
        kernel.CloseHandle.argtypes = [W.HANDLE]
        self.kernel, self.handle = kernel, kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.get_last_error()
            self.close()
            raise ctypes.WinError(error)

    def attach(self, child):
        # Popen owns this exact handle, not a process found by name/PID scan.
        if not self.kernel.AssignProcessToJobObject(self.handle, W.HANDLE(int(child._handle))):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def worker_command(generation):
    pythonw = Path(sys.executable).with_name('pythonw.exe')
    if not pythonw.is_file() or pythonw.resolve() != pythonw.absolute():
        raise RuntimeError('invalid_python_runtime')
    return [str(pythonw), '-I', str(ROOT / 'dns_service.py'), '--worker',
            '--generation', generation, '--supervisor-pid', str(os.getpid())]


class Supervisor:
    def __init__(self, spawn=None, make_job=None, publish=None, logger=None):
        self.spawn = spawn or (lambda command: subprocess.Popen(command,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW))
        self.make_job = make_job or OwnedWorkerJob
        self.publish = publish or (lambda value: atomic_state('supervisor.json', value))
        self.logger = logger or log_state
        self.child = self.job = None
        self.generation = None
        self.started = self.next_start = self.last_publish = 0
        self.failures = self.starts = 0

    def state(self, status, **extra):
        return dict(schema_version=1, role='supervisor', pid=os.getpid(),
                    worker_pid=self.child.pid if self.child else None,
                    generation=self.generation, worker_starts=self.starts,
                    consecutive_short_exits=self.failures, status=status,
                    retries_use_direct_fallback=False, **extra)

    def step(self, now):
        if self.child is not None:
            result = self.child.poll()
            if result is None:
                if now - self.last_publish >= 5:
                    self.publish(self.state('worker_alive'))
                    self.last_publish = now
                return
            uptime = max(0, now - self.started)
            self.job.close()
            self.child = self.job = None
            self.failures = 1 if uptime >= 30 else self.failures + 1
            delay = min(2 ** min(self.failures - 1, 5), 30)
            self.next_start = now + delay
            self.logger('owned_worker_exited', exit_code=result, retry_seconds=delay)
            self.publish(self.state('retry_wait', retry_seconds=delay))
            return
        if now < self.next_start:
            return
        self.generation = uuid.uuid4().hex
        job = self.make_job()
        child = None
        try:
            child = self.spawn(worker_command(self.generation))
            job.attach(child)
        except Exception:
            if child is not None:
                child.terminate()
                child.wait(timeout=5)
            job.close()
            raise
        self.child, self.job = child, job
        self.started = self.last_publish = now
        self.starts += 1
        self.publish(self.state('worker_started'))
        self.logger('owned_worker_started', worker_pid=child.pid, starts=self.starts)

    def close(self):
        if self.job:
            self.job.close()
        self.publish(self.state('supervisor_stopped'))


def run_worker(generation, supervisor_pid):
    if len(generation) != 32 or any(c not in '0123456789abcdef' for c in generation) or supervisor_pid <= 0:
        raise ValueError('invalid_worker_identity')
    physical_root()
    sys.path.insert(0, str(DNS))
    from scoped_dns_stub import serve
    value = dict(schema_version=1, role='worker', pid=os.getpid(),
                 supervisor_pid=supervisor_pid, generation=generation,
                 script=str(DNS / 'scoped_dns_stub.py'), launcher=str(ROOT / 'dns_service.py'),
                 port=53, pythonw=sys.executable, ready=False)
    atomic_state('process.json', value)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    with (DNS / 'service.log').open('a', encoding='utf-8') as log:
        sys.stdout = sys.stderr = log
        try:
            serve(53, 17894, stop_event=stop,
                  on_ready=lambda: atomic_state('process.json', dict(value, ready=True)))
        except OSError:
            log_state('worker_listener_or_socket_failed_no_fallback')
            return 70
        finally:
            atomic_state('process.json', dict(value, ready=False))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--generation', default='')
    parser.add_argument('--supervisor-pid', type=int, default=0)
    args = parser.parse_args(argv)
    physical_root()
    if args.worker:
        return run_worker(args.generation, args.supervisor_pid)
    if args.generation or args.supervisor_pid:
        raise ValueError('worker_arguments_require_worker_mode')
    instance = SingleInstance()
    if not instance.acquired:
        instance.close()
        return 0
    supervisor = Supervisor()
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        log_state('supervisor_started', pid=os.getpid())
        while not stop.wait(.5):
            supervisor.step(time.monotonic())
    except Exception:
        log_state('supervisor_failed_no_fallback')
        return 71
    finally:
        supervisor.close()
        instance.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
