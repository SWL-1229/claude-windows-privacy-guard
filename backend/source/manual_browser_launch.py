"""Ordinary manually operated Edge, with an independent native policy watcher.

Never attaches a debugger, evaluates page JavaScript, changes fingerprints,
solves challenges, logs in, or reads browser account/cookie storage.
"""
from pathlib import Path
import ctypes as C
from ctypes import wintypes as W
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time

import environment_lease as leases
import environment_watchdog as watchdog
import manual_browser_policy as policy
from browser_system_timezone import require_eastern_system_timezone
from environment_launch import LaunchFailure

LOADED_SHA = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


class BootstrapMutex:
    def __init__(self, root):
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.kernel.CreateMutexW.argtypes = [C.c_void_p, W.BOOL, W.LPCWSTR]
        self.kernel.CreateMutexW.restype = W.HANDLE
        self.kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
        self.kernel.WaitForSingleObject.restype = W.DWORD
        self.kernel.ReleaseMutex.argtypes = [W.HANDLE]
        self.kernel.CloseHandle.argtypes = [W.HANDLE]
        name = 'Local\\ClaudeManualBrowserBootstrap-' + hashlib.sha256(str(root).encode()).hexdigest()[:32]
        self.handle = self.kernel.CreateMutexW(None, False, name)
        self.owned = False
        if not self.handle or self.kernel.WaitForSingleObject(self.handle, 30000) not in (0, 0x80):
            self.close()
            raise LaunchFailure('existing_environment_requires_restart')
        self.owned = True

    def release(self):
        if self.owned:
            self.kernel.ReleaseMutex(self.handle)
            self.owned = False

    def close(self):
        self.release()
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def stamp(value=None):
    import datetime as dt
    return dt.datetime.fromtimestamp(time.time() if value is None else value, dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def backend(root):
    path = leases.physical(root / 'native-launcher/native_desktop_launch.py', root)
    spec = importlib.util.spec_from_file_location('manual_browser_services', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.WindowsBackend(root)


def publish(path, baseline, target, *, state='monitoring'):
    now = stamp()
    leases.atomic_json(path, {'schema_version': 1, 'kind': 'browser', 'verification_mode': policy.MODE,
        'environment_scope': policy.SCOPE, 'process_pid': target['pid'], 'status': state,
        'native_baseline': baseline, 'controller_heartbeat_checked_at': now, 'at': now,
        'error_codes': [], 'page_javascript_measured': False, 'ice_candidates_measured': False})


def existing(root):
    for file in (root / 'environment-leases').glob('browser-*.registration.json'):
        try:
            record = leases.read_json(file, root)
            if record.get('verification_mode') != policy.MODE or not leases.alive(record['target']):
                continue
            monitor = watchdog.active_monitor('browser', record['target'], root=root, verification_mode=policy.MODE)
            if monitor is None:
                raise LaunchFailure('existing_environment_requires_restart')
            policy.observation(root, record['target'], record['controller'], record['source'], record=record)
            return record
        except LaunchFailure:
            raise
        except Exception:
            continue
    return None


def require_profile_unused(service, root):
    profile = os.path.normcase(str(root / 'browser-profiles/edge-claude'))
    rows = service.powershell("[pscustomobject]@{rows=@(Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | Select-Object ProcessId,CommandLine)} | ConvertTo-Json -Depth 4 -Compress")['rows']
    if not isinstance(rows, list):
        return
    for row in rows:
        args = service.guard.windows_command_line_args(row.get('CommandLine') or '')
        if any(arg.startswith('--user-data-dir=') and os.path.normcase(arg.split('=', 1)[1]) == profile for arg in args):
            raise LaunchFailure('existing_environment_requires_restart')


def open_manual_page(runtime, root):
    # Normal Chromium single-instance handoff, with no debugger or remote input.
    return subprocess.Popen([runtime['browser_executable'], *policy.arguments(root, 'https://claude.ai/')],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=0x08000000)


def run(root, mutex):
    root = leases.physical(Path(root), Path(root))
    runtime = leases.read_json(root / 'environment-runtime.json', root)
    service = backend(root)
    service.ensure_services()
    from browser_system_timezone import WindowsTimezoneReader, _eastern
    if not _eastern(WindowsTimezoneReader().read_timezone()):
        raise LaunchFailure('wrong_timezone')
    current = existing(root)
    if current:
        open_manual_page(runtime, root)
        return
    require_profile_unused(service, root)
    policy.prepare_webrtc_preferences(root)
    profile = root / 'browser-profiles/edge-claude'
    profile.mkdir(parents=True, exist_ok=True)
    leases.physical(profile, root)
    process = subprocess.Popen([runtime['browser_executable'], *policy.arguments(root)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=0x08000000)
    controller = leases.identity(os.getpid())
    target = None
    for _ in range(30):
        target = leases.identity(process.pid)
        if target:
            break
        if process.poll() is not None:
            break
        time.sleep(.1)
    if (not target or os.path.normcase(target['image']) != os.path.normcase(runtime['browser_executable'])
            or leases.parents().get(target['pid']) != controller['pid']):
        raise LaunchFailure('existing_environment_requires_restart')
    status = root / 'privacy-qa/runs' / f"environment-browser-{controller['pid']}.json"
    require_eastern_system_timezone(target, controller, identify=leases.identity, same_identity=leases.same_identity)
    policy.actual_arguments(root, target, controller, leases)
    baseline = {'schema': 1, 'scope': policy.SCOPE, 'checked_at': stamp(),
                'timezone': policy.ZONE, 'windows_timezone': policy.WINDOWS_ZONE,
                'language_preference': 'en-US,en', 'launcher_sha256': LOADED_SHA}
    publish(status, baseline, target)
    stop = threading.Event()
    def heartbeat():
        while not stop.wait(.4):
            if not leases.alive(target):
                return
            try:
                publish(status, baseline, target)
            except Exception:
                return  # Watchdog/guard revoke stale evidence independently.
    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        registered = watchdog.start_monitor('browser', target, controller=controller,
            status_path=status, root=root, verification_mode=policy.MODE)
        # This is the same four-second exit lease and independent guard gate.
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                service.guard.verified_gate_for_launch()
                break
            except Exception:
                time.sleep(.2)
        else:
            raise LaunchFailure('protected_gate_not_verified')
        leases.atomic_json(root / 'manual-browser-current.json', {
            'schema': 1, 'outcome': 'manual-native-policy-ready', 'verification_mode': policy.MODE,
            'target': target, 'controller': controller, 'status_path': str(status),
            'page_javascript_measured': False, 'automation_control_running': False,
            'fingerprint_overrides_installed': False, 'checked_at': stamp()})
        open_manual_page(runtime, root)
        mutex.release()
        while leases.alive(target):
            time.sleep(.5)
    finally:
        stop.set()
        # Leave login/profile data and unrelated registrations untouched.
        try:
            publish(status, baseline, target, state='stopped')
        except Exception:
            pass


def main(root):
    root = leases.physical(Path(root), Path(root))
    mutex = BootstrapMutex(root)
    try:
        return run(root, mutex)
    finally:
        mutex.close()
