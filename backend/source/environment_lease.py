"""Process-bound environment leases and private-browser peer attribution.

No profile/authentication reads. A lost lease never makes a registered private
browser eligible for the ordinary proxy route. All on-disk values are observations
bound to live process creation times, not authority to expand the exit allowlist.
"""
from pathlib import Path
import ctypes as C
import datetime as dt
from ctypes import wintypes as W
from contextlib import contextmanager
import hashlib
import json
import math
import os
import re
import secrets
import socket
import struct
import threading
import time

ROOT = Path(__file__).resolve().parent
TTL = 4.0
NATIVE_BROWSER_MODE = 'native_process_policy_v1'
NATIVE_BROWSER_SCOPE = 'native-browser-process-policy-v1'
NATIVE_BROWSER_REASON = 'native_browser_policy_verified'
RTC_COUNT_FIELDS = frozenset(('total','privateIPv4','linkLocalIPv4','loopbackIPv4','publicIPv4',
    'ulaIPv6','linkLocalIPv6','loopbackIPv6','globalIPv6','unspecifiedIPv4','unspecifiedIPv6',
    'mdns','noAddress','otherAddress','host','srflx','prflx','relay','unknownType'))
RTC_RAW_FIELDS = frozenset(('privateIPv4','linkLocalIPv4','loopbackIPv4','publicIPv4',
    'ulaIPv6','linkLocalIPv6','loopbackIPv6','globalIPv6','otherAddress'))


def native_startup_fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                                    ensure_ascii=True).encode('ascii')).hexdigest()


def native_browser_source(value, record, now):
    """A fresh control heartbeat with an immutable, historical startup check.

    This never claims a new JS/runtime observation. Only the native watchdog
    may publish a fresh policy lease after its independent actual OS/argv read.
    """
    if (record.get('kind')!='browser' or record.get('verification_mode')!=NATIVE_BROWSER_MODE
            or type(value) is not dict or type(value.get('schema_version')) is not int
            or value['schema_version']!=1 or value.get('kind')!='browser'
            or value.get('verification_mode')!=NATIVE_BROWSER_MODE
            or value.get('environment_scope')!=NATIVE_BROWSER_SCOPE
            or type(value.get('process_pid')) is not int or value['process_pid']!=record['target']['pid']
            or value.get('status')!='monitoring' or value.get('error_codes')!=[]
            or type(value.get('activation_complete')) is not bool or value.get('environment_check_ok') is not True
            or type(value.get('counts')) is not dict
            or type(value['counts'].get('metadata_mismatches')) is not int
            or value['counts']['metadata_mismatches']!=0
            or value.get('navigation_guard') is not None or value.get('suspension_guard') is not None):
        raise LeaseError('native_browser_source_invalid')
    startup=value.get('startup_runtime')
    if (type(startup) is not dict or set(startup)!= {'schema','scope','checked_at','environment','rtc','accepted'}
            or type(startup.get('schema')) is not int or startup['schema']!=1
            or startup.get('scope')!='initial-about-blank-no-stun-v1' or startup.get('accepted') is not True):
        raise LeaseError('native_browser_startup_invalid')
    env=startup.get('environment')
    if (type(env) is not dict or set(env)!= {'timeZone','locale','language','languages','januaryOffset','julyOffset'}
            or env.get('timeZone')!='America/New_York' or env.get('locale') not in ('en-US','en_US')
            or env.get('language')!='en-US' or env.get('languages')!=['en-US','en']
            or type(env.get('januaryOffset')) is not int or env['januaryOffset']!=300
            or type(env.get('julyOffset')) is not int or env['julyOffset']!=240):
        raise LeaseError('native_browser_startup_invalid')
    rtc=startup.get('rtc')
    if (type(rtc) is not dict or set(rtc)!= {'status','gatheringComplete','statsAvailable','events','sdp','stats'}
            or type(rtc.get('gatheringComplete')) is not bool or type(rtc.get('statsAvailable')) is not bool):
        raise LeaseError('native_browser_startup_invalid')
    for name in ('events','sdp','stats'):
        counts=rtc.get(name)
        if (type(counts) is not dict or set(counts)!=RTC_COUNT_FIELDS
                or any(type(v) is not int or not 0<=v<=2048 for v in counts.values())
                or any(counts[k]!=0 for k in RTC_RAW_FIELDS)):
            raise LeaseError('native_browser_startup_invalid')
    if not ((rtc['status']=='complete' and rtc['gatheringComplete'] and rtc['statsAvailable'])
            or (rtc['status']=='api_unavailable' and not rtc['gatheringComplete'] and not rtc['statsAvailable']
                and all(v==0 for name in ('events','sdp','stats') for v in rtc[name].values()))):
        raise LeaseError('native_browser_startup_invalid')
    checked=_suspension_timestamp(startup.get('checked_at'))
    heartbeat=_suspension_timestamp(value.get('controller_heartbeat_checked_at'))
    published=_suspension_timestamp(value.get('at'))
    created=int(record['target']['creation'],16)/10000000-11644473600
    if (checked!=record.get('bootstrap_checked_at')
            or checked!=_suspension_timestamp(value.get('startup_runtime_checked_at'))
            or checked!=_suspension_timestamp(value.get('environment_check_at'))
            or native_startup_fingerprint(startup)!=record.get('startup_runtime_sha256')
            or not created<=checked<=heartbeat<=published<=now
            or not 0<=now-heartbeat<=TTL or not 0<=now-published<=TTL):
        raise LeaseError('native_browser_source_expired_or_changed')
    return {'bootstrap_checked_at':checked,'heartbeat_checked_at':heartbeat}
SUSPENSION_MAX_SECONDS = 30.0
SUSPENSION_FIELDS = frozenset(('schema', 'mode', 'started_at', 'checked_at', 'deadline_at',
    'first_runtime_checked_at', 'configuration_generation', 'inventory_complete',
    'inventory_fingerprint', 'target_count'))


def _suspension_timestamp(value):
    if type(value) is not str or len(value) != 24 or not value.endswith('Z'):
        raise LeaseError('browser_suspension_proof_invalid')
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + '+00:00')
        if parsed.isoformat(timespec='milliseconds').replace('+00:00', 'Z') != value:
            raise ValueError()
        return parsed.timestamp()
    except (ValueError, OverflowError):
        raise LeaseError('browser_suspension_proof_invalid') from None


def suspension_bootstrap(record, now):
    created = int(record['target']['creation'], 16) / 10000000 - 11644473600
    bootstrap, registered = record.get('bootstrap_checked_at'), record.get('registered_at')
    if (any(type(v) not in (int, float) or not math.isfinite(v) for v in (bootstrap, registered))
            or not created <= bootstrap <= registered <= now or registered - bootstrap > TTL):
        raise LeaseError('browser_suspension_bootstrap_invalid')
    return created, bootstrap


def suspension_proof(value, *, now, created, bootstrap, runtime_checked_at):
    """Control-plane heartbeat only; it never authorizes application bytes."""
    if (type(value) is not dict or set(value) != SUSPENSION_FIELDS
            or type(value.get('schema')) is not int or value['schema'] != 1
            or value.get('mode') != 'zero_byte_scope_transition'
            or value.get('inventory_complete') is not True
            or type(value.get('configuration_generation')) is not int
            or not 1 <= value['configuration_generation'] <= 9007199254740991
            or type(value.get('target_count')) is not int or not 1 <= value['target_count'] <= 4096
            or type(value.get('inventory_fingerprint')) is not str
            or re.fullmatch('[a-f0-9]{64}', value['inventory_fingerprint']) is None):
        raise LeaseError('browser_suspension_proof_invalid')
    started, checked, deadline, baseline = (_suspension_timestamp(value[k]) for k in
        ('started_at', 'checked_at', 'deadline_at', 'first_runtime_checked_at'))
    if (type(runtime_checked_at) not in (int, float) or not math.isfinite(runtime_checked_at)
            or not created <= bootstrap <= baseline <= started < deadline <= started + SUSPENSION_MAX_SECONDS
            or baseline != runtime_checked_at or not started <= now < deadline
            or not created <= checked <= now or not 0 <= now - checked <= TTL):
        raise LeaseError('browser_suspension_proof_expired')
    return {'phase': tuple(value[k] for k in ('started_at', 'deadline_at', 'first_runtime_checked_at')),
            'started': started, 'checked': checked, 'deadline': deadline, 'baseline': baseline}


def suspension_source(value, record, proof, now, *, allow_recovered=False):
    """Validate the owned publisher's current hard-failure flags and heartbeat."""
    created, bootstrap = suspension_bootstrap(record, now)
    counts, codes = value.get('counts'), value.get('error_codes')
    healthy = ((value.get('status') == 'monitoring' and codes == [])
               or (value.get('status') == 'partial' and codes == ['early_unpaused_target']))
    if (type(value.get('schema_version')) is not int or value['schema_version'] != 1
            or value.get('kind') != 'browser' or type(value.get('process_pid')) is not int
            or value['process_pid'] != record['target']['pid']
            or value.get('environment_scope') != 'isolated-browser-all-web-targets-v1'
            or value.get('activation_complete') is not True or not healthy
            or type(counts) is not dict or any(type(counts.get(k)) is not int or counts[k] != 0 for k in
                ('metadata_mismatches', 'command_errors', 'workers_unverified', 'unprotected_targets',
                 'unknown_target_types', 'environment_check_failures'))):
        raise LeaseError('browser_suspension_source_invalid')
    published = _suspension_timestamp(value.get('at'))
    runtime_checked = _suspension_timestamp(value.get('environment_check_at'))
    if not created <= runtime_checked <= published <= now or not 0 <= now - published <= TTL:
        raise LeaseError('browser_suspension_source_expired')
    if (allow_recovered and value.get('environment_check_ok') is True
            and value.get('environment_check_pending') is False
            and value.get('last_environment_diagnostic') == 'verified'
            and value.get('navigation_guard') is None and value.get('suspension_guard') is None
            and 0 <= now - runtime_checked <= TTL):
        old = suspension_proof(proof, now=now, created=created, bootstrap=bootstrap,
                               runtime_checked_at=_suspension_timestamp(proof['first_runtime_checked_at']))
        if runtime_checked < old['started']:
            raise LeaseError('browser_suspension_recovery_not_new')
        return {'checked': runtime_checked, 'recovered': True, 'phase': old['phase']}
    if (value.get('environment_check_ok') is not False or value.get('environment_check_pending') is not True
            or value.get('last_environment_diagnostic') not in ('scope_changed', 'configuration_changed',
                'navigation_configuration_pending', 'navigation_deadline_expired', 'metadata_unavailable',
                'navigation_binding_unavailable')
            or type(value.get('configuration_generation')) is not int
            or not 1 <= value['configuration_generation'] <= 9007199254740991):
        raise LeaseError('browser_suspension_source_invalid')
    current = suspension_proof(value.get('suspension_guard'), now=now, created=created,
                               bootstrap=bootstrap, runtime_checked_at=runtime_checked)
    if value['suspension_guard']['configuration_generation'] > value['configuration_generation']:
        raise LeaseError('browser_suspension_source_invalid')
    expected = suspension_proof(proof, now=now, created=created, bootstrap=bootstrap,
                               runtime_checked_at=_suspension_timestamp(proof['first_runtime_checked_at']))
    if current['phase'] != expected['phase']:
        raise LeaseError('browser_suspension_phase_changed')
    return current
MAX_RECORDS = 32
MAX_SCAN_FILES = 4096
MAX_JSON_BYTES = 32768
FILE_LOCK_TIMEOUT_MS = 100
_io_metrics_lock = threading.Lock()
_io_metrics = {'acquisitions': 0, 'timeouts': 0, 'abandoned': 0,
               'max_wait_ms': 0.0, 'max_hold_ms': 0.0}


class LeaseError(RuntimeError):
    pass


class _FileInfo(C.Structure):
    _fields_ = [('attributes', W.DWORD), ('created', W.FILETIME),
                ('accessed', W.FILETIME), ('written', W.FILETIME),
                ('volume', W.DWORD), ('size_high', W.DWORD),
                ('size_low', W.DWORD), ('links', W.DWORD),
                ('index_high', W.DWORD), ('index_low', W.DWORD)]


_file_kernel = None


def _file_api():
    global _file_kernel
    if _file_kernel is not None:
        return _file_kernel
    k = C.WinDLL('kernel32', use_last_error=True)
    k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p,
                             W.DWORD, W.DWORD, W.HANDLE]
    k.CreateFileW.restype = W.HANDLE
    k.GetFileInformationByHandle.argtypes = [W.HANDLE, C.POINTER(_FileInfo)]
    k.GetFileInformationByHandle.restype = W.BOOL
    k.GetFinalPathNameByHandleW.argtypes = [W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD]
    k.GetFinalPathNameByHandleW.restype = W.DWORD
    k.GetFileType.argtypes = [W.HANDLE]
    k.GetFileType.restype = W.DWORD
    k.ReadFile.argtypes = [W.HANDLE, C.c_void_p, W.DWORD,
                           C.POINTER(W.DWORD), C.c_void_p]
    k.ReadFile.restype = W.BOOL
    k.SetFileInformationByHandle.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD]
    k.SetFileInformationByHandle.restype = W.BOOL
    k.CloseHandle.argtypes = [W.HANDLE]
    k.CloseHandle.restype = W.BOOL
    k.CreateMutexW.argtypes = [C.c_void_p, W.BOOL, W.LPCWSTR]
    k.CreateMutexW.restype = W.HANDLE
    k.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
    k.WaitForSingleObject.restype = W.DWORD
    k.ReleaseMutex.argtypes = [W.HANDLE]
    k.ReleaseMutex.restype = W.BOOL
    _file_kernel = k
    return k


def _lexical(path, boundary=ROOT):
    p, b = Path(path).absolute(), Path(boundary).absolute()
    if '..' in p.parts or '..' in b.parts or not p.is_relative_to(b):
        raise LeaseError('lease_path_invalid')
    return p


def io_diagnostics(*, reset=False):
    """Safe, aggregate timing metadata only; no filenames or record contents."""
    with _io_metrics_lock:
        value = dict(_io_metrics, timeout_limit_ms=FILE_LOCK_TIMEOUT_MS)
        if reset:
            _io_metrics.update(acquisitions=0, timeouts=0, abandoned=0,
                               max_wait_ms=0.0, max_hold_ms=0.0)
        return value


@contextmanager
def _file_lock(path):
    if os.name != 'nt':
        yield
        return
    k = _file_api()
    canonical = os.path.normcase(os.path.abspath(path))
    name = 'Local\\ClaudeGuardJsonIO-' + hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    handle = k.CreateMutexW(None, False, name)
    if not handle:
        raise LeaseError('lease_io_lock_unavailable')
    owned, acquired_at = False, None
    try:
        began = time.perf_counter()
        outcome = k.WaitForSingleObject(handle, FILE_LOCK_TIMEOUT_MS)
        waited = (time.perf_counter() - began) * 1000
        with _io_metrics_lock:
            _io_metrics['max_wait_ms'] = max(_io_metrics['max_wait_ms'], waited)
            if outcome in (0, 0x80):
                _io_metrics['acquisitions'] += 1
                _io_metrics['abandoned'] += int(outcome == 0x80)
            elif outcome == 0x102:
                _io_metrics['timeouts'] += 1
        if outcome not in (0, 0x80):
            raise LeaseError('lease_io_lock_timeout' if outcome == 0x102 else 'lease_io_lock_unavailable')
        # WAIT_ABANDONED grants ownership, but grants no permission exemption.
        # The caller still checks actual path, JSON/schema, nonce and freshness.
        owned, acquired_at = True, time.perf_counter()
        yield
    finally:
        released = True
        if owned:
            held = (time.perf_counter() - acquired_at) * 1000
            with _io_metrics_lock:
                _io_metrics['max_hold_ms'] = max(_io_metrics['max_hold_ms'], held)
            released = bool(k.ReleaseMutex(handle))
        k.CloseHandle(handle)
        if not released:
            raise LeaseError('lease_io_lock_release_failed')


def _validate_opened_file(k, handle, path, boundary):
    info = _FileInfo()
    if not k.GetFileInformationByHandle(handle, C.byref(info)):
        raise C.WinError(C.get_last_error())
    if info.attributes & (0x400 | 0x10) or k.GetFileType(handle) != 1:
        raise LeaseError('lease_path_invalid')
    name = C.create_unicode_buffer(32768)
    length = k.GetFinalPathNameByHandleW(handle, name, len(name), 0)
    if not 0 < length < len(name):
        raise C.WinError(C.get_last_error())
    actual = name.value
    if actual.startswith('\\\\?\\UNC\\'):
        actual = '\\\\' + actual[8:]
    elif actual.startswith('\\\\?\\'):
        actual = actual[4:]
    if (os.path.normcase(os.path.abspath(actual)) != os.path.normcase(os.path.abspath(path))
            or not Path(actual).is_relative_to(Path(boundary).absolute())):
        raise LeaseError('lease_path_invalid')
    return info


def physical(path, boundary=ROOT, missing=False):
    p, b = Path(path).absolute(), Path(boundary).absolute()
    if not p.is_relative_to(b) or p.resolve(strict=not missing) != p:
        raise LeaseError('lease_path_invalid')
    return p


def _read_failure(error):
    if isinstance(error, LeaseError):
        return error
    code = getattr(error, 'winerror', None)
    if isinstance(error, FileNotFoundError) or code in (2, 3):
        return LeaseError('lease_record_missing')
    if code in (32, 33):
        return LeaseError('lease_record_sharing_violation')
    if isinstance(error, PermissionError) or code == 5:
        return LeaseError('lease_record_access_denied')
    return LeaseError('lease_record_read_unavailable')


def _failure_code(error):
    # A diagnostic enum only: never publish exception text, paths or contents.
    allowed = {'lease_path_invalid', 'lease_record_too_large', 'lease_record_missing',
               'lease_record_sharing_violation', 'lease_record_access_denied',
               'lease_record_read_unavailable', 'lease_record_invalid_json',
               'lease_record_invalid', 'lease_registration_invalid',
               'lease_io_lock_timeout', 'lease_io_lock_unavailable',
               'lease_io_lock_release_failed', 'lease_atomic_replace_unavailable',
               'lease_identity_invalid', 'lease_kind_invalid', 'lease_nonce_invalid',
               'lease_audit_directory_too_large', 'too_many_active_or_uncertain_leases',
               'process_identity_unavailable', 'private_process_identity_invalid',
               'private_process_tree_too_large', 'process_tree_unavailable'}
    if isinstance(error, LeaseError) and str(error) in allowed:
        return str(error)
    if isinstance(error, OSError):
        return str(_read_failure(error))
    return 'lease_validation_unavailable'


def _windows_json_bytes(path, boundary):
    """Read one bounded file snapshot without denying atomic replacement.

    Python's normal Windows file open omits FILE_SHARE_DELETE. A fast lease
    reader could therefore deny os.replace in the independent monitor. Open
    with all three share modes, reject reparse/directory handles, and verify
    the actual opened path before reading. The old immutable snapshot remains
    readable if another process atomically replaces the pathname meanwhile.
    """
    k = _file_api()
    handle = k.CreateFileW(str(path), 0x80000000, 0x1 | 0x2 | 0x4, None,
                           3, 0x00200000 | 0x08000000, None)
    if handle == W.HANDLE(-1).value:
        raise C.WinError(C.get_last_error())
    try:
        info = _validate_opened_file(k, handle, path, boundary)
        if ((info.size_high << 32) | info.size_low) > MAX_JSON_BYTES:
            raise LeaseError('lease_record_too_large')
        data, count = C.create_string_buffer(MAX_JSON_BYTES + 1), W.DWORD()
        if not k.ReadFile(handle, data, MAX_JSON_BYTES + 1, C.byref(count), None):
            raise C.WinError(C.get_last_error())
        if count.value > MAX_JSON_BYTES:
            raise LeaseError('lease_record_too_large')
        return data.raw[:count.value]
    finally:
        k.CloseHandle(handle)


def read_json(path, boundary=ROOT):
    p = _lexical(path, boundary)
    with _file_lock(p):
        return _read_json_unlocked(p, boundary)


def _read_json_unlocked(path, boundary):
    try:
        if os.name == 'nt':
            # Path.resolve itself opens a Windows handle without DELETE share.
            # Validate the final opened object instead of hot-opening the leaf
            # once for resolve and then a second time for the actual read.
            p = _lexical(path, boundary)
            data = _windows_json_bytes(p, boundary)
        else:
            p = physical(path, boundary)
            # The Windows service uses the handle path above. Keep bounded
            # account-free fixtures portable, without unbounded read_text.
            with p.open('rb') as stream:
                data = stream.read(MAX_JSON_BYTES + 1)
            if len(data) > MAX_JSON_BYTES:
                raise LeaseError('lease_record_too_large')
    except Exception as error:
        raise _read_failure(error) from None
    try:
        value = json.loads(data.decode('utf-8-sig'))
    except (UnicodeError, ValueError):
        raise LeaseError('lease_record_invalid_json') from None
    if not isinstance(value, dict):
        raise LeaseError('lease_record_invalid')
    return value


def _windows_replace(source, target):
    """Win10+ atomic replace that permits open FILE_SHARE_DELETE readers."""
    k = _file_api()
    handle = k.CreateFileW(str(source), 0x80000000 | 0x00010000,
                           0x1 | 0x2 | 0x4, None, 3, 0x00200000, None)
    if handle == W.HANDLE(-1).value:
        raise C.WinError(C.get_last_error())
    try:
        _validate_opened_file(k, handle, source, ROOT)
        encoded = str(target).encode('utf-16-le')
        # FILE_RENAME_INFO: DWORD Flags, x64 HANDLE RootDirectory, DWORD
        # FileNameLength, WCHAR FileName[]. The ABI offsets are 0/8/16/20.
        if C.sizeof(W.HANDLE) != 8:
            raise LeaseError('lease_atomic_replace_unavailable')
        # KernelBase's FileRenameInfoEx conversion also consults the trailing
        # WCHAR terminator; reserve it even though FileNameLength excludes it.
        info = C.create_string_buffer(20 + len(encoded) + 2)
        struct.pack_into('<I', info, 0, 0x1 | 0x2)  # REPLACE_IF_EXISTS | POSIX_SEMANTICS
        struct.pack_into('<Q', info, 8, 0)
        struct.pack_into('<I', info, 16, len(encoded))
        C.memmove(C.addressof(info) + 20, encoded, len(encoded))
        if not k.SetFileInformationByHandle(handle, 22, info, len(info)):
            raise C.WinError(C.get_last_error())
    finally:
        k.CloseHandle(handle)


def atomic_json(path, value):
    p = _lexical(path)
    with _file_lock(p):
        return _atomic_json_unlocked(p, value)


def _atomic_json_unlocked(path, value):
    p = _lexical(path) if os.name == 'nt' else physical(path, missing=True)
    p.parent.mkdir(exist_ok=True)
    physical(p.parent)
    if p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction()):
        raise LeaseError('lease_path_invalid')
    data = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(data) > MAX_JSON_BYTES:
        raise LeaseError('lease_record_too_large')
    # A unique CREATE_NEW temporary file also avoids same-process writer
    # threads sharing the old PID-only temporary filename.
    temp = p.with_name(p.name + '.' + str(os.getpid()) + '.' + secrets.token_hex(8) + '.tmp')
    physical(temp, missing=True)
    try:
        with temp.open('xb') as f:
            f.write(data)
            f.flush()
        # Correctly shared readers need no retry. A bounded retry tolerates a
        # transient legacy/AV handle without ever retaining an old permission.
        for attempt in range(3):
            try:
                if os.name == 'nt':
                    _windows_replace(temp, p)
                else:
                    os.replace(temp, p)
                break
            except OSError as error:
                if getattr(error, 'winerror', None) not in (32, 33) or attempt == 2:
                    raise
                time.sleep(.001 * (attempt + 1))
    finally:
        if temp.exists():
            try:
                physical(temp).unlink()
            except (OSError, LeaseError):
                pass


def identity(pid):
    if type(pid) is not int or pid <= 0:
        raise LeaseError('process_identity_invalid')
    k = C.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    k.OpenProcess.restype = W.HANDLE
    k.GetProcessTimes.argtypes = [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4
    k.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
    k.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    k.CloseHandle.argtypes = [W.HANDLE]
    handle = k.OpenProcess(0x1000, False, pid)
    if not handle:
        if C.get_last_error() == 87:
            return None
        raise LeaseError('process_identity_unavailable')
    try:
        code = W.DWORD()
        if not k.GetExitCodeProcess(handle, C.byref(code)):
            raise LeaseError('process_identity_unavailable')
        if code.value != 259:
            return None
        created, exited, kernel, user = [W.FILETIME() for _ in range(4)]
        name, size = C.create_unicode_buffer(32768), W.DWORD(32768)
        if (not k.GetProcessTimes(handle, *[C.byref(x) for x in (created, exited, kernel, user)])
                or not k.QueryFullProcessImageNameW(handle, 0, name, C.byref(size))):
            raise LeaseError('process_identity_unavailable')
        stamp = (created.dwHighDateTime << 32) | created.dwLowDateTime
        return {'pid': pid, 'creation': f'{stamp:016x}', 'image': os.path.normcase(os.path.abspath(name.value))}
    finally:
        k.CloseHandle(handle)



class _ProcessHead(C.Structure):
    # Windows x64 SYSTEM_PROCESS_INFORMATION prefix through parent PID.
    class _UnicodeString(C.Structure):
        _fields_ = [('length', W.USHORT), ('maximum', W.USHORT), ('buffer', C.c_void_p)]
    _fields_ = [('next', W.ULONG), ('threads', W.ULONG),
                ('working_private', C.c_longlong), ('hard_faults', W.ULONG),
                ('high_threads', W.ULONG), ('cycles', C.c_ulonglong),
                ('created', C.c_longlong), ('user', C.c_longlong),
                ('kernel', C.c_longlong), ('name', _UnicodeString),
                ('priority', C.c_long), ('pid', C.c_void_p), ('parent', C.c_void_p)]


def process_creations():
    """Kernel PID/FILETIME snapshot without opening protected processes.

    A mismatched birth is only evidence of PID reuse, never an admission grant.
    No names, full paths, command lines, or user/account data are returned.
    """
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8 or _ProcessHead.created.offset != 32 or _ProcessHead.pid.offset != 80:
        raise LeaseError('process_creation_snapshot_unsupported')
    n = C.WinDLL('ntdll')
    query = n.NtQuerySystemInformation
    query.argtypes = [W.ULONG, C.c_void_p, W.ULONG, C.POINTER(W.ULONG)]
    query.restype = C.c_long
    size = 1024 * 1024
    for _ in range(5):
        buffer, needed = C.create_string_buffer(size), W.ULONG()
        status = query(5, buffer, size, C.byref(needed))
        if (status & 0xffffffff) == 0xc0000004:
            size = max(size * 2, needed.value + 65536)
            if size > 64 * 1024 * 1024:
                break
            continue
        if status != 0 or not C.sizeof(_ProcessHead) <= needed.value <= size:
            raise LeaseError('process_creation_snapshot_unavailable')
        result, offset = {}, 0
        for _ in range(65536):
            if offset + C.sizeof(_ProcessHead) > needed.value:
                raise LeaseError('process_creation_snapshot_invalid')
            head = _ProcessHead.from_buffer(buffer, offset)
            pid, created, advance = int(head.pid or 0), int(head.created), int(head.next)
            if pid:
                if pid in result or created < 0:
                    raise LeaseError('process_creation_snapshot_invalid')
                result[pid] = created
            if advance == 0:
                # Refuse an unknown Windows layout rather than using offsets
                # speculatively; current self FILETIME is an independent API.
                own = identity(os.getpid())
                if own is None or result.get(os.getpid()) != int(own['creation'], 16):
                    raise LeaseError('process_creation_snapshot_invalid')
                return result
            if advance < C.sizeof(_ProcessHead) or advance % 8 or offset + advance >= needed.value:
                raise LeaseError('process_creation_snapshot_invalid')
            offset += advance
        raise LeaseError('process_creation_snapshot_invalid')
    raise LeaseError('process_creation_snapshot_unavailable')


def same_identity(wanted, actual):
    return bool(actual and wanted['pid'] == actual['pid'] and wanted['creation'] == actual['creation']
                and os.path.normcase(wanted['image']) == os.path.normcase(actual['image']))


def alive(wanted):
    return same_identity(wanted, identity(wanted['pid']))


def validate_identity(value):
    if (not isinstance(value, dict) or type(value.get('pid')) is not int or value['pid'] <= 0
            or not re.fullmatch('[0-9a-f]{16}', value.get('creation', ''))
            or not isinstance(value.get('image'), str) or not Path(value['image']).is_absolute()):
        raise LeaseError('lease_identity_invalid')
    return value


def key_for(kind, target):
    if kind not in ('native', 'browser'):
        raise LeaseError('lease_kind_invalid')
    validate_identity(target)
    return f"{kind}-{target['pid']}-{target['creation']}"


def paths(kind, target, nonce, root=ROOT):
    if not re.fullmatch('[0-9a-f]{32}', nonce):
        raise LeaseError('lease_nonce_invalid')
    base = Path(root) / 'environment-leases'
    key = key_for(kind, target)
    return base / (key + '.registration.json'), base / (key + '-' + nonce + '.lease.json')


def register(kind, target, monitor, nonce, source=None, root=ROOT, initial_checked_at=None,
             verification_mode=None, controller=None, bootstrap_checked_at=None,
             startup_runtime_sha256=None, native_arguments_sha256=None):
    validate_identity(target)
    validate_identity(monitor)
    if not alive(target) or not alive(monitor):
        raise LeaseError('lease_process_not_alive')
    record_path, lease_path = paths(kind, target, nonce, root)
    record = {'schema': 1, 'kind': kind, 'target': target, 'monitor': monitor, 'nonce': nonce,
              'lease_name': lease_path.name, 'source': source, 'registered_at': time.time()}
    if verification_mode is not None:
        if (verification_mode!=NATIVE_BROWSER_MODE or kind!='browser' or initial_checked_at is None
                or type(bootstrap_checked_at) not in (int,float) or not math.isfinite(bootstrap_checked_at)
                or not 0<=time.time()-bootstrap_checked_at<=TTL
                or any(type(v) is not str or re.fullmatch('[0-9a-f]{64}',v) is None
                       for v in (startup_runtime_sha256,native_arguments_sha256))):
            raise LeaseError('native_browser_registration_invalid')
        controller=validate_identity(controller)
        if (not alive(controller) or parents().get(target['pid'])!=controller['pid']
                or int(controller['creation'],16)>int(target['creation'],16)
                or Path(source)!=Path(root)/'privacy-qa'/'runs'/f"environment-browser-{controller['pid']}.json"):
            raise LeaseError('native_browser_registration_invalid')
        record.update(verification_mode=verification_mode,controller=controller,
                      startup_runtime_sha256=startup_runtime_sha256,
                      native_arguments_sha256=native_arguments_sha256)
    if initial_checked_at is not None:
        if (type(initial_checked_at) not in (int, float)
                or not 0 <= time.time() - initial_checked_at <= TTL):
            raise LeaseError('initial_environment_check_expired')
        if kind == 'browser':
            created = int(target['creation'], 16) / 10000000 - 11644473600
            if not math.isfinite(initial_checked_at) or initial_checked_at < created:
                raise LeaseError('initial_environment_check_expired')
            record['bootstrap_checked_at'] = bootstrap_checked_at if verification_mode is not None else initial_checked_at
        # Publish an already-verified observation before making the new
        # registration visible. A replacement is never briefly an empty lease.
        atomic_json(lease_path, {'schema': 1, 'nonce': nonce, 'ok': True,
                                'checked_at': initial_checked_at, 'written_at': time.time(),
                                'reason': NATIVE_BROWSER_REASON if verification_mode is not None else 'verified'})
    atomic_json(record_path, record)
    return record_path, lease_path


def write_lease(record_path, lease_path, nonce, ok, checked_at, reason='verified', root=ROOT,
                suspension_guard=None):
    record = read_json(record_path, root)
    if record.get('nonce') != nonce or not same_identity(record['monitor'], identity(os.getpid())):
        raise LeaseError('lease_superseded')
    if record.get('verification_mode') is not None:
        if (record.get('verification_mode')!=NATIVE_BROWSER_MODE or record.get('kind')!='browser'
                or (ok is True and reason!=NATIVE_BROWSER_REASON) or suspension_guard is not None
                or reason in ('browser_scope_transition_pending','browser_scope_suspension_pending')):
            raise LeaseError('native_browser_lease_invalid')
    result = {'schema': 1, 'nonce': nonce, 'ok': bool(ok),
                            'checked_at': checked_at, 'written_at': time.time(),
                            'reason': reason if re.fullmatch('[a-z0-9_]{1,64}', reason) else 'check_failed'}
    if suspension_guard is not None:
        if record.get('kind') != 'browser' or ok is not False or reason != 'browser_scope_suspension_pending':
            raise LeaseError('browser_suspension_lease_invalid')
        created, bootstrap = suspension_bootstrap(record, time.time())
        suspension_proof(suspension_guard, now=time.time(), created=created,
                         bootstrap=bootstrap, runtime_checked_at=checked_at)
        result['suspension_guard'] = dict(suspension_guard)
    atomic_json(lease_path, result)


def parents():
    class Entry(C.Structure):
        _fields_ = [('dwSize', W.DWORD), ('cntUsage', W.DWORD), ('pid', W.DWORD),
                    ('heap', C.c_size_t), ('module', W.DWORD), ('threads', W.DWORD),
                    ('parent', W.DWORD), ('priority', W.LONG), ('flags', W.DWORD),
                    ('name', W.WCHAR * 260)]
    k = C.WinDLL('kernel32', use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes = [W.DWORD, W.DWORD]
    k.CreateToolhelp32Snapshot.restype = W.HANDLE
    k.Process32FirstW.argtypes = [W.HANDLE, C.POINTER(Entry)]
    k.Process32NextW.argtypes = [W.HANDLE, C.POINTER(Entry)]
    k.CloseHandle.argtypes = [W.HANDLE]
    snap = k.CreateToolhelp32Snapshot(2, 0)
    if snap == W.HANDLE(-1).value:
        raise LeaseError('process_tree_unavailable')
    result = {}
    try:
        e = Entry(); e.dwSize = C.sizeof(e)
        more = k.Process32FirstW(snap, C.byref(e))
        while more:
            result[int(e.pid)] = int(e.parent)
            more = k.Process32NextW(snap, C.byref(e))
        return result
    finally:
        k.CloseHandle(snap)


def peer_pid(peer, server_port):
    if not peer or peer[0] != '127.0.0.1':
        raise LeaseError('proxy_peer_not_loopback')
    api = C.WinDLL('iphlpapi', use_last_error=True)
    api.GetExtendedTcpTable.argtypes = [C.c_void_p, C.POINTER(W.DWORD), W.BOOL, W.ULONG, C.c_int, W.ULONG]
    api.GetExtendedTcpTable.restype = W.DWORD
    size = W.DWORD()
    code = api.GetExtendedTcpTable(None, C.byref(size), False, 2, 5, 0)
    if code != 122 or size.value > 16 * 1024 * 1024:
        raise LeaseError('proxy_peer_identity_unavailable')
    for _ in range(3):
        buf = C.create_string_buffer(size.value)
        code = api.GetExtendedTcpTable(buf, C.byref(size), False, 2, 5, 0)
        if code == 122:
            continue
        if code:
            raise LeaseError('proxy_peer_identity_unavailable')
        raw = buf.raw
        count = struct.unpack_from('<I', raw)[0]
        if 4 + count * 24 > len(raw):
            raise LeaseError('proxy_peer_identity_unavailable')
        matches = set()
        for i in range(count):
            state, la, lp, ra, rp, pid = struct.unpack_from('<6I', raw, 4 + i * 24)
            if (socket.inet_ntoa(struct.pack('<I', la)) == '127.0.0.1'
                    and socket.inet_ntoa(struct.pack('<I', ra)) == '127.0.0.1'
                    and socket.ntohs(lp & 65535) == peer[1]
                    and socket.ntohs(rp & 65535) == server_port and state == 5):
                matches.add(pid)
        if len(matches) != 1:
            raise LeaseError('proxy_peer_identity_unavailable')
        return matches.pop()
    raise LeaseError('proxy_peer_identity_unavailable')


class LeaseRegistry:
    def __init__(self, root=ROOT, *, get_identity=identity, get_parents=parents,
                 get_peer=peer_pid, clock=time.time, get_creations=None):
        self.root = Path(root)
        self.get_identity, self.get_parents, self.get_peer, self.clock = get_identity, get_parents, get_peer, clock
        # Test fixtures injecting identity can explicitly inject a creation map;
        # otherwise they retain their original synthetic-process behavior.
        self.get_creations = process_creations if get_creations is None and get_identity is identity else get_creations
        self.creation_snapshot = None
        self.records, self.last_scan, self.scan_error = {}, -1.0, False
        self.scan_failure_reason, self.last_failure = None, None
        # Retired filenames contain PID + exact creation time; that identity can
        # never become live again. Keep files for audit, without counting them as
        # active registrations or repeatedly opening old process identities.
        self.retired = set()
        self.descendants = {}

    def _current(self, pid, wanted, identities):
        existing = identities.get(pid)
        if (existing and existing.get('_creation_only') is True and wanted is not None
                and existing['creation'] == wanted['creation']):
            identities.pop(pid)
        if pid not in identities:
            created = None if self.creation_snapshot is None else self.creation_snapshot.get(pid)
            if self.creation_snapshot is not None and created is None:
                identities[pid] = None
            elif wanted is not None and created is not None and created != int(wanted['creation'], 16):
                # Deliberately incomplete identity; different FILETIME proves it
                # cannot equal this wanted process. Never admitted as a match.
                identities[pid] = {'pid': pid, 'creation': f'{created:016x}',
                                   'image': os.path.abspath(os.devnull), '_creation_only': True}
            else:
                identities[pid] = self.get_identity(pid)
        return identities[pid]

    def _lineage(self, pid, target, tree):
        result, seen = [], set()
        for _ in range(64):
            if not pid or pid in seen:
                return None
            seen.add(pid)
            result.append(pid)
            if pid == target['pid']:
                return result
            pid = tree.get(pid, 0)
        return None

    def _belongs(self, pid, target, tree, identities):
        lineage = self._lineage(pid, target, tree)
        if lineage is None:
            return False
        # First establish the numerical parent chain. Do not inspect unrelated
        # System ancestors of an ordinary proxy client.
        def current(value):
            if value not in identities:
                identities[value] = self.get_identity(value)
            return identities[value]
        root = self._current(target['pid'], target, identities)
        if len(lineage) == 1:
            return same_identity(target, root)
        minimum = int(target['creation'], 16)
        upper = None
        if root is not None and not same_identity(target, root):
            upper = int(root['creation'], 16)
            if upper <= minimum:
                raise LeaseError('private_process_identity_invalid')
        if self.creation_snapshot is not None:
            births = [self.creation_snapshot.get(i) for i in lineage[:-1]]
            if any(stamp is None or stamp <= 0 or stamp < minimum or (upper is not None and stamp >= upper) for stamp in births):
                return False
            if any(child < parent for child, parent in zip(births, births[1:])):
                return False
        infos = [current(i) for i in lineage[:-1]]
        if any(i is None for i in infos):
            return False
        if any(os.path.normcase(i['image']) != os.path.normcase(target['image']) for i in infos):
            return False
        stamps = [int(i['creation'], 16) for i in infos]
        if any(stamp < minimum or (upper is not None and stamp >= upper) for stamp in stamps):
            return False
        # A reused intermediate parent must not attach a newer process tree to
        # an old protected instance. Already-observed children remain sticky.
        if any(child < parent for child, parent in zip(stamps, stamps[1:])):
            return False
        return True

    def _live_descendants(self, name, target, tree, identities):
        known = self.descendants.setdefault(name, {})
        for pid, wanted in list(known.items()):
            self._current(pid, wanted, identities)
            if not same_identity(wanted, identities[pid]):
                known.pop(pid, None)
        # Traverse only descendants of the registered numeric parent. Never
        # enumerate identity/paths of the rest of the machine's process tree.
        children = {}
        for child, parent in tree.items():
            children.setdefault(parent, []).append(child)
        pending = list(children.get(target['pid'], ()))
        seen = set()
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            if len(seen) > 4096:
                raise LeaseError('private_process_tree_too_large')
            pending.extend(children.get(pid, ()))
            if self._belongs(pid, target, tree, identities):
                known[pid] = identities[pid]
        return bool(known)

    def scan(self, *, force=False):
        now = self.clock()
        if not force and 0 <= now - self.last_scan < .1:
            return
        self.last_scan, self.scan_error, self.scan_failure_reason = now, False, None
        base = self.root / 'environment-leases'
        if not base.exists():
            self.scan_error = bool(self.records)
            if self.scan_error:
                self.scan_failure_reason = 'registration_directory_missing'
            return
        try:
            physical(base, self.root)
            files = []
            for file in base.glob('*.registration.json'):
                files.append(file)
                if len(files) > MAX_SCAN_FILES:
                    raise LeaseError('lease_audit_directory_too_large')
            found = set()
            for file in files:
                if file.name in self.retired:
                    continue
                r = read_json(file, self.root)
                target, monitor = validate_identity(r.get('target')), validate_identity(r.get('monitor'))
                expected, lease = paths(r.get('kind'), target, r.get('nonce', ''), self.root)
                if (r.get('schema') != 1 or file != expected or r.get('lease_name') != lease.name):
                    raise LeaseError('lease_registration_invalid')
                found.add(file.name)
                self.records[file.name] = (r, lease, True)
            # Deleting a live registration is a failure, never a route downgrade.
            for name, (r, lease, present) in list(self.records.items()):
                if name not in found:
                    self.records[name] = (r, lease, False)
            identities = {}
            self.creation_snapshot = self.get_creations() if self.records and self.get_creations is not None else None
            if self.creation_snapshot is not None and (not isinstance(self.creation_snapshot, dict) or any(
                    type(pid) is not int or pid <= 0 or type(stamp) is not int or stamp < 0
                    for pid, stamp in self.creation_snapshot.items())):
                raise LeaseError('process_creation_snapshot_invalid')
            tree = self.get_parents() if self.records else {}
            for name, (r, lease, present) in list(self.records.items()):
                target, monitor = r['target'], r['monitor']
                has_children = self._live_descendants(name, target, tree, identities)
                for identity_value in (target, monitor):
                    pid = identity_value['pid']
                    self._current(pid, identity_value, identities)
                if (not same_identity(target, identities[target['pid']])
                        and not same_identity(monitor, identities[monitor['pid']]) and not has_children):
                    # Nothing from this exact instance can use a lease again.
                    # Retire only in memory; no registration/lease/config files
                    # are deleted, so concurrent replacement cannot be removed.
                    self.retired.add(name)
                    self.records.pop(name, None)
                    self.descendants.pop(name, None)
            if len(self.records) > MAX_RECORDS:
                raise LeaseError('too_many_active_or_uncertain_leases')
        except Exception as error:
            self.scan_error = True
            self.scan_failure_reason = _failure_code(error)

    def active(self):
        self.scan()
        result = []
        tree, identities = None, {}
        for name, (r, lease, present) in self.records.items():
            current = self._current(r['target']['pid'], r['target'], identities)
            if same_identity(r['target'], current):
                result.append((r, lease, present))
            else:
                if tree is None:
                    tree = self.get_parents()
                if self._live_descendants(name, r['target'], tree, identities):
                    # Orphaned network/render processes keep the instance bound
                    # to its failed environment until every owned child exits.
                    result.append((r, lease, present))
        return result

    def permitted(self):
        context = None
        native_measurements=[]

        def deny(reason, checked_age=None, written_age=None):
            def finite(value):
                return value if type(value) in (int, float) and math.isfinite(value) else None
            self.last_failure = {
                'reason': reason,
                'kind': context.get('kind') if context and context.get('kind') in ('native', 'browser') else None,
                'target_pid': context.get('target', {}).get('pid') if context else None,
                'checked_age': finite(checked_age), 'written_age': finite(written_age)}
            return False

        try:
            active = self.active()
            if self.scan_error:
                return deny(self.scan_failure_reason or 'lease_registry_unavailable')
            for r, path, present in active:
                context = r
                if not present:
                    return deny('registration_missing')
                if not same_identity(r['target'], self.get_identity(r['target']['pid'])):
                    return deny('target_identity_invalid')
                if not same_identity(r['monitor'], self.get_identity(r['monitor']['pid'])):
                    return deny('monitor_identity_invalid')
                lease = read_json(path, self.root)
                # Snapshot time only after the immutable lease was read. A
                # concurrent monitor can legitimately publish after an older
                # pre-read clock sample; that is not a future-dated lease.
                now = self.clock()
                if (lease.get('schema') != 1 or lease.get('nonce') != r['nonce'] or lease.get('ok') is not True
                        or type(lease.get('checked_at')) not in (int, float)
                        or type(lease.get('written_at')) not in (int, float)):
                    return deny('lease_content_invalid')
                checked_age, written_age = now - lease['checked_at'], now - lease['written_at']
                if not 0 <= checked_age <= TTL or not 0 <= written_age <= TTL:
                    return deny('lease_expired_or_clock_invalid', checked_age, written_age)
                if r.get('verification_mode') is not None:
                    native_evidence=self._native_browser_policy_record(r,lease)
                    native_measurements.extend((lease['checked_at'],lease['written_at'],native_evidence['heartbeat_checked_at']))
                    now=self.clock()
                    if not 0<=now-lease['checked_at']<=TTL or not 0<=now-lease['written_at']<=TTL:
                        return deny('lease_expired_or_clock_invalid')
                elif lease.get('reason')==NATIVE_BROWSER_REASON:
                    return deny('native_browser_mode_missing')
            final_now=self.clock()
            if any(not 0<=final_now-value<=TTL for value in native_measurements):
                return deny('lease_expired_or_clock_invalid')
            self.last_failure = None
            return True
        except Exception as error:
            return deny(_failure_code(error))

    def transmission_state(self):
        """Distinguish permission from a bounded, byte-blocking suspension.

        `suspended` is not admission. Only the transport owner may retain its
        existing sockets while forwarding zero bytes and anchoring a deadline.
        The returned signature pins the complete active registration set.
        """
        def deny(reason):
            return {'state': 'denied', 'signature': None, 'reason': reason}

        try:
            # A changed or removed registration must not inherit a previous
            # suspension signature from the ordinary 100 ms scan cache.
            self.scan(force=True)
            active = self.active()
            if self.scan_error:
                return deny('registry_scan_failed')
            identities, measurements, deadlines, phases, pending = [], [], [], [], False
            native_process_policy_only = bool(active)
            verified_environment_only = bool(active)
            runtime_checks, all_actual_runtime = [], True
            suspension_checks, suspension_runtimes, suspension_writes = [], [], []
            for record, path, present in active:
                if record.get('verification_mode') != NATIVE_BROWSER_MODE or record.get('kind') != 'browser':
                    native_process_policy_only = False
                if (type(record.get('schema')) is not int or record['schema'] != 1
                        or record.get('kind') not in ('browser', 'native')
                        or type(record.get('nonce')) is not str
                        or re.fullmatch('[a-f0-9]{32}', record['nonce']) is None
                        or not present or not same_identity(record['target'], self.get_identity(record['target']['pid']))
                        or not same_identity(record['monitor'], self.get_identity(record['monitor']['pid']))):
                    return deny('registration_or_identity_invalid')
                lease = read_json(path, self.root)
                # A separate explicit contract for the off-thread observer.
                # Older browser continuity modes retain their existing path;
                # only actual desktop runtime leases and the independently
                # validated native-browser policy may use this snapshot.
                if not ((record.get('kind') == 'native'
                         and record.get('verification_mode') is None
                         and lease.get('reason') == 'verified')
                        or (record.get('kind') == 'browser'
                            and record.get('verification_mode') == NATIVE_BROWSER_MODE)):
                    verified_environment_only = False
                now = self.clock()
                if (type(lease.get('schema')) is not int or lease['schema'] != 1
                        or lease.get('nonce') != record['nonce'] or type(lease.get('ok')) is not bool
                        or any(type(lease.get(field)) not in (int, float)
                               or not math.isfinite(lease[field])
                               for field in ('checked_at', 'written_at'))):
                    return deny('lease_content_invalid')
                fresh = [lease['written_at']]
                if record.get('verification_mode') is not None:
                    native_evidence=self._native_browser_policy_record(record,lease)
                    fresh.append(native_evidence['heartbeat_checked_at'])
                elif lease.get('reason')==NATIVE_BROWSER_REASON:
                    return deny('native_browser_mode_missing')
                if lease['ok'] is False:
                    if record['kind'] != 'browser' or not self._transition_source(record):
                        return deny('browser_false_or_controller_invalid')
                    if lease.get('reason') == 'browser_scope_suspension_pending':
                        created, bootstrap = suspension_bootstrap(record, self.clock())
                        proof = suspension_proof(lease.get('suspension_guard'), now=self.clock(),
                            created=created, bootstrap=bootstrap, runtime_checked_at=lease['checked_at'])
                        source = read_json(Path(record['source']), self.root)
                        source_proof = suspension_source(source, record, lease['suspension_guard'],
                            self.clock(), allow_recovered=True)
                        fresh.extend((proof['checked'], source_proof['checked']))
                        suspension_checks.extend((proof['checked'], source_proof['checked']))
                        deadlines.append(proof['deadline'])
                        phases.append({'target': record['target'], 'nonce': record['nonce'],
                                       'phase': proof['phase'], 'started': proof['started']})
                    elif lease.get('reason') == 'browser_scope_transition_pending':
                        fresh.append(lease['checked_at'])
                        suspension_checks.append(lease['checked_at'])
                        deadlines.append(lease['checked_at'] + TTL)
                    else:
                        return deny('false_lease_not_suspendable')
                    suspension_runtimes.append(lease['checked_at'])
                    suspension_writes.append(lease['written_at'])
                    pending = True
                else:
                    if 'suspension_guard' in lease:
                        return deny('true_lease_has_suspension_data')
                    fresh.append(lease['checked_at'])
                    if record['kind'] == 'browser':
                        if lease.get('reason') == 'verified':
                            runtime_checks.append(lease['checked_at'])
                        else:
                            all_actual_runtime = False
                now = self.clock()
                if any(not 0 <= now - measured <= TTL for measured in fresh):
                    return deny('lease_heartbeat_or_runtime_expired')
                identities.append({field: record.get(field) for field in
                                   ('kind', 'target', 'monitor', 'nonce', 'source', 'bootstrap_checked_at',
                                    'verification_mode','controller','startup_runtime_sha256','native_arguments_sha256')})
                measurements.extend(fresh)
            now = self.clock()
            if any(now >= deadline for deadline in deadlines):
                return deny('suspension_deadline_expired')
            if any(not 0 <= now - measured <= TTL for measured in measurements):
                return deny('lease_heartbeat_or_runtime_expired')
            identities.sort(key=lambda item: (item['kind'], item['target']['pid'],
                                               item['target']['creation'], item['nonce']))
            signature = hashlib.sha256(json.dumps(identities, sort_keys=True,
                separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
            result = {'state': 'suspended' if pending else 'permitted', 'signature': signature,
                      'browser_runtime_verified_at': min(runtime_checks) if runtime_checks and all_actual_runtime and not pending else None,
                      'reason': 'zero_byte_suspension' if phases else 'legacy_scope_transition' if pending
                                else 'verified_environment_leases' if active else 'no_active_registered_environment'}
            if native_process_policy_only and not pending and measurements:
                # Actual original lease/source observations, never publication.
                result.update(native_process_policy_only=True, policy_valid_until=min(measurements)+TTL,
                              policy_observed_not_before=max(measurements))
            if verified_environment_only and not pending and measurements:
                # Preserve the original checked/written/source observations.
                # Re-scanning or publishing a snapshot never extends a lease.
                result.update(verified_environment_only=True,
                              environment_valid_until=min(measurements)+TTL,
                              environment_observed_not_before=max(measurements))
            if pending:
                result.update(suspension_checked_at=min(suspension_checks),
                              suspension_runtime_checked_at=min(suspension_runtimes),
                              suspension_written_at=min(suspension_writes))
            if phases:
                phases.sort(key=lambda item: (item['target']['pid'], item['target']['creation'], item['nonce']))
                result.update(suspension_phase=hashlib.sha256(json.dumps(phases, sort_keys=True,
                    separators=(',', ':')).encode('ascii')).hexdigest(),
                    suspension_deadline=min(deadlines), suspension_started_at=max(p['started'] for p in phases))
            return result
        except Exception as error:
            code = str(error) if isinstance(error, LeaseError) else None
            known = {'browser_suspension_bootstrap_invalid', 'browser_suspension_proof_invalid',
                     'browser_suspension_proof_expired', 'browser_suspension_source_invalid',
                     'browser_suspension_source_expired', 'browser_suspension_recovery_not_new',
                     'browser_suspension_phase_changed','native_browser_registration_invalid',
                     'native_browser_lease_invalid','native_browser_source_invalid',
                     'native_browser_startup_invalid','native_browser_source_expired_or_changed'}
            return deny(code if code in known else 'registry_observation_failed')

    def _native_browser_policy_record(self,record,lease):
        if (record.get('verification_mode')!=NATIVE_BROWSER_MODE or record.get('kind')!='browser'
                or lease.get('ok') is not True or lease.get('reason')!=NATIVE_BROWSER_REASON
                or 'suspension_guard' in lease
                or not self._transition_source(record)
                or not same_identity(record.get('controller'),self.get_identity(record.get('controller',{}).get('pid')))):
            raise LeaseError('native_browser_lease_invalid')
        if any(type(record.get(k)) is not str or re.fullmatch('[0-9a-f]{64}',record[k]) is None
               for k in ('startup_runtime_sha256','native_arguments_sha256')):
            raise LeaseError('native_browser_registration_invalid')
        source=read_json(Path(record['source']),self.root)
        evidence=native_browser_source(source,record,self.clock())
        # Original bootstrap was fresh at registration; ongoing policy checks
        # do not mutate or renew that historical browser JS observation.
        suspension_bootstrap(record,self.clock())
        return evidence

    def _transition_source(self, record):
        # The known monitor produced the false signal after its own fresh
        # WinAPI and runtime-baseline checks. Bind it to the owned controller's
        # exact source and process tree; a native lease cannot use this path.
        source = record.get('source')
        if type(source) is not str:
            return False
        match = re.fullmatch(r'environment-browser-([1-9][0-9]*)\.json', Path(source).name)
        if not match:
            return False
        pid = int(match.group(1))
        expected = self.root / 'privacy-qa' / 'runs' / f'environment-browser-{pid}.json'
        if Path(source) != expected:
            return False
        runtime = read_json(self.root / 'environment-runtime.json', self.root)
        controller = self.get_identity(pid)
        if (controller is None or os.path.normcase(controller['image']) != os.path.normcase(runtime['node_executable'])
                or os.path.normcase(record['target']['image']) != os.path.normcase(runtime['browser_executable'])
                or int(controller['creation'], 16) > int(record['target']['creation'], 16)
                or self.get_parents().get(record['target']['pid']) != pid):
            return False
        # Re-query identity after reading the runtime/path and parent chain.
        return same_identity(controller, self.get_identity(pid))

    def scoped_peer(self, peer, server_port):
        # Even invalid/expired leases keep the browser on the guarded route.
        # Admission must observe a just-committed registration. Reusing the
        # periodic scan's 100 ms cache could issue an ordinary long-lived tunnel
        # to a newly registered browser before its first guarded request.
        self.scan(force=True)
        if self.scan_error:
            raise LeaseError('lease_registry_unavailable')
        browser_roots = [(name, r['target']) for name, (r, _, _) in self.records.items() if r['kind'] == 'browser']
        if not browser_roots:
            return False
        pid = self.get_peer(peer, server_port)
        tree = self.get_parents()
        identities = {}
        for name, target in browser_roots:
            known = self.descendants.setdefault(name, {})
            wanted = known.get(pid)
            sticky = wanted is not None and same_identity(wanted, self.get_identity(pid))
            if sticky or self._belongs(pid, target, tree, identities):
                if not same_identity(target, self.get_identity(target['pid'])):
                    raise LeaseError('private_browser_parent_exited')
                actual = self.get_identity(pid)
                if actual is None:
                    raise LeaseError('private_browser_peer_exited')
                if pid != target['pid']:
                    known[pid] = actual
                return True
        return False
