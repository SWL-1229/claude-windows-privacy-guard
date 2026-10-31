"""Read-only current Win32 timezone and same-session checks for browser leases.

No cache of timezone observations, clock mutation, registry writes, UI, network,
process launch, arbitrary code execution, or caller-supplied file operation.
"""
import ctypes as C
from ctypes import wintypes as W
import os
import re
import hashlib
import json
from pathlib import Path


class HostTimezoneError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


NATIVE_BROWSER_MODE = 'native_process_policy_v1'


def native_browser_arguments(root):
    """The one trusted browser policy; not a per-profile WFP isolation claim."""
    root = Path(root)
    if not root.is_absolute() or '..' in root.parts:
        raise HostTimezoneError('native_browser_root_invalid')
    return ['--user-data-dir=' + str(root / 'browser-profiles' / 'edge-claude'),
        '--no-first-run', '--no-default-browser-check', '--disable-sync',
        '--disable-extensions', '--disable-background-networking',
        '--disable-component-update', '--disable-default-apps',
        '--proxy-server=http://127.0.0.1:17894', '--proxy-bypass-list=<-loopback>',
        '--disable-quic', '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
        '--lang=en-US', '--accept-lang=en-US,en',
        '--edge-skip-compat-layer-relaunch', 'about:blank']


class UNICODE_STRING(C.Structure):
    _fields_ = [('Length', W.USHORT), ('MaximumLength', W.USHORT), ('Buffer', C.c_void_p)]


class WindowsProcessArgumentsReader:
    """Read a single process's actual arguments without shell, WMI or writes."""
    MAX_BUFFER = 131072

    def __init__(self):
        try:
            if os.name != 'nt' or C.sizeof(C.c_void_p) != 8 or C.sizeof(C.c_wchar) != 2:
                raise ValueError()
            self.kernel = C.WinDLL('kernel32', use_last_error=True)
            self.ntdll = C.WinDLL('ntdll')
            self.shell = C.WinDLL('shell32', use_last_error=True)
            self.kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
            self.kernel.OpenProcess.restype = W.HANDLE
            self.kernel.CloseHandle.argtypes = [W.HANDLE]
            self.kernel.CloseHandle.restype = W.BOOL
            self.kernel.LocalFree.argtypes = [C.c_void_p]
            self.kernel.LocalFree.restype = C.c_void_p
            self.query = self.ntdll.NtQueryInformationProcess
            self.query.argtypes = [W.HANDLE, W.ULONG, C.c_void_p, W.ULONG, C.POINTER(W.ULONG)]
            self.query.restype = W.LONG
            self.parse = self.shell.CommandLineToArgvW
            self.parse.argtypes = [W.LPCWSTR, C.POINTER(C.c_int)]
            self.parse.restype = C.POINTER(W.LPWSTR)
        except Exception:
            raise HostTimezoneError('native_browser_arguments_unavailable') from None

    def read_arguments(self, pid):
        handle = None
        parsed = None
        try:
            if type(pid) is not int or not 0 < pid < 0xffffffff:
                raise ValueError()
            # Query-only handle: no VM writes, injection, process termination or
            # token changes. Class 60 returns a local UNICODE_STRING buffer.
            handle = self.kernel.OpenProcess(0x1400, False, pid)
            if not handle:
                raise ValueError()
            required = W.ULONG()
            self.query(handle, 60, None, 0, C.byref(required))
            size = int(required.value)
            if not C.sizeof(UNICODE_STRING) < size <= self.MAX_BUFFER:
                raise ValueError()
            buffer = C.create_string_buffer(size)
            if self.query(handle, 60, buffer, size, C.byref(required)) < 0:
                raise ValueError()
            if not C.sizeof(UNICODE_STRING) <= required.value <= size:
                raise ValueError()
            value = UNICODE_STRING.from_buffer(buffer)
            start = C.addressof(buffer)
            pointer = value.Buffer or 0
            if (not 0 < value.Length <= value.MaximumLength <= 65534
                    or value.Length % 2 or pointer % 2
                    or pointer < start + C.sizeof(UNICODE_STRING)
                    or pointer + value.MaximumLength > start + size):
                raise ValueError()
            command = C.wstring_at(pointer, value.Length // 2)
            if any(c in command for c in '\0\r\n'):
                raise ValueError()
            count = C.c_int()
            parsed = self.parse(command, C.byref(count))
            if not parsed or not 1 <= count.value <= 64:
                raise ValueError()
            result = [parsed[i] for i in range(count.value)]
            if any(type(arg) is not str or not arg or len(arg) > 32767 for arg in result):
                raise ValueError()
            return result
        except Exception:
            raise HostTimezoneError('native_browser_arguments_unavailable') from None
        finally:
            if parsed:
                self.kernel.LocalFree(C.cast(parsed, C.c_void_p))
            if handle:
                self.kernel.CloseHandle(handle)


def require_native_browser_arguments(target, controller, *, root, identify, same_identity, reader=None):
    """Validate the actual fixed policy on one exact, still-owned browser.

    Only a hash and the fixed profile are returned. Neither the original command
    line nor arbitrary argument/exception text is persisted or logged.
    """
    try:
        if not _valid_identity(target) or not _valid_identity(controller):
            raise HostTimezoneError('native_browser_identity_unverified')
        root = Path(root)
        profile = root / 'browser-profiles' / 'edge-claude'
        if (not root.is_absolute() or '..' in root.parts
                or root.resolve(strict=True) != root.absolute()
                or not profile.is_dir() or profile.resolve(strict=True) != profile.absolute()):
            raise HostTimezoneError('native_browser_profile_invalid')
        for item in (target, controller):
            if same_identity(item, identify(item['pid'])) is not True:
                raise HostTimezoneError('native_browser_identity_unverified')
        api = WindowsProcessArgumentsReader() if reader is None else reader
        actual = api.read_arguments(target['pid'])
        expected = native_browser_arguments(root) + ['--remote-debugging-pipe']
        if (type(actual) is not list or len(actual) != len(expected) + 1
                or any(type(arg) is not str or any(c in arg for c in '\0\r\n') for arg in actual)
                or os.path.normcase(os.path.normpath(actual[0])) != os.path.normcase(os.path.normpath(target['image']))
                or actual[1:] != expected):
            raise HostTimezoneError('native_browser_arguments_mismatch')
        for item in (target, controller):
            if same_identity(item, identify(item['pid'])) is not True:
                raise HostTimezoneError('native_browser_identity_unverified')
        return {'arguments_sha256': hashlib.sha256(json.dumps(actual, ensure_ascii=True,
                    separators=(',', ':')).encode('ascii')).hexdigest(), 'profile': str(profile)}
    except HostTimezoneError:
        raise
    except Exception:
        raise HostTimezoneError('native_browser_arguments_unavailable') from None


class SYSTEMTIME(C.Structure):
    _fields_ = [(name, W.WORD) for name in (
        'wYear', 'wMonth', 'wDayOfWeek', 'wDay', 'wHour', 'wMinute',
        'wSecond', 'wMilliseconds')]


class DYNAMIC_TIME_ZONE_INFORMATION(C.Structure):
    _fields_ = [('Bias', W.LONG), ('StandardName', W.WCHAR * 32),
        ('StandardDate', SYSTEMTIME), ('StandardBias', W.LONG),
        ('DaylightName', W.WCHAR * 32), ('DaylightDate', SYSTEMTIME),
        ('DaylightBias', W.LONG), ('TimeZoneKeyName', W.WCHAR * 128),
        ('DynamicDaylightTimeDisabled', C.c_ubyte)]


STANDARD_RULE = (0, 11, 0, 1, 2, 0, 0, 0)
DAYLIGHT_RULE = (0, 3, 0, 2, 2, 0, 0, 0)


def _rule(value):
    return tuple(int(getattr(value, name)) for name, _ in SYSTEMTIME._fields_)


class WindowsTimezoneReader:
    def __init__(self):
        try:
            if (os.name != 'nt' or C.sizeof(SYSTEMTIME) != 16
                    or C.sizeof(DYNAMIC_TIME_ZONE_INFORMATION) != 432
                    or DYNAMIC_TIME_ZONE_INFORMATION.DynamicDaylightTimeDisabled.offset != 428):
                raise ValueError()
            self.kernel = C.WinDLL('kernel32', use_last_error=True)
            self.timezone = self.kernel.GetDynamicTimeZoneInformation
            self.timezone.argtypes = [C.POINTER(DYNAMIC_TIME_ZONE_INFORMATION)]
            self.timezone.restype = W.DWORD
            self.session = self.kernel.ProcessIdToSessionId
            self.session.argtypes = [W.DWORD, C.POINTER(W.DWORD)]
            self.session.restype = W.BOOL
        except Exception:
            raise HostTimezoneError('browser_system_timezone_unavailable') from None

    def read_timezone(self):
        try:
            value = DYNAMIC_TIME_ZONE_INFORMATION()
            code = int(self.timezone(C.byref(value)))
            if code == 0xffffffff:
                raise ValueError()
            # Localized StandardName/DaylightName are neither used nor returned.
            return {'result': code, 'key': value.TimeZoneKeyName,
                'bias': int(value.Bias), 'standard_bias': int(value.StandardBias),
                'daylight_bias': int(value.DaylightBias),
                'dynamic_dst_disabled': int(value.DynamicDaylightTimeDisabled),
                'standard_rule': _rule(value.StandardDate),
                'daylight_rule': _rule(value.DaylightDate)}
        except Exception:
            raise HostTimezoneError('browser_system_timezone_unavailable') from None

    def session_id(self, pid):
        try:
            value = W.DWORD()
            if type(pid) is not int or not 0 < pid < 0xffffffff or not self.session(pid, C.byref(value)):
                raise ValueError()
            return int(value.value)
        except Exception:
            raise HostTimezoneError('browser_system_session_unavailable') from None


def _valid_identity(value):
    return (type(value) is dict and type(value.get('pid')) is int
        and 0 < value['pid'] < 0xffffffff and type(value.get('creation')) is str
        and re.fullmatch('[0-9a-f]{16}', value['creation']) is not None
        and type(value.get('image')) is str and bool(value['image']))


def _eastern(value):
    return (type(value) is dict and type(value.get('result')) is int
        and value['result'] in (1, 2) and value.get('key') == 'Eastern Standard Time'
        and type(value.get('bias')) is int and value['bias'] == 300
        and type(value.get('standard_bias')) is int and value['standard_bias'] == 0
        and type(value.get('daylight_bias')) is int and value['daylight_bias'] == -60
        and type(value.get('dynamic_dst_disabled')) is int and value['dynamic_dst_disabled'] == 0
        and type(value.get('standard_rule')) in (tuple, list)
        and type(value.get('daylight_rule')) in (tuple, list)
        and tuple(value['standard_rule']) == STANDARD_RULE
        and tuple(value['daylight_rule']) == DAYLIGHT_RULE
        and all(type(n) is int for n in (*value['standard_rule'], *value['daylight_rule'])))


def require_eastern_system_timezone(target, controller, *, identify, same_identity,
                                    reader=None, current_pid=None):
    """Read a new host observation and bind it to exact same-session identities.

    Callbacks are the watcher's private identity implementation, not values
    supplied by a browser or report. No timestamp is returned: this observation
    must never refresh a renderer runtime timestamp or navigation deadline.
    """
    pid = os.getpid() if current_pid is None else current_pid
    try:
        if not _valid_identity(target) or not _valid_identity(controller) or type(pid) is not int or pid <= 0:
            raise HostTimezoneError('browser_system_identity_unverified')
        owner = identify(pid)
        if not _valid_identity(owner):
            raise HostTimezoneError('browser_system_identity_unverified')
        expected = (target, controller, owner)
        for identity in expected:
            actual = identify(identity['pid'])
            if not _valid_identity(actual) or same_identity(identity, actual) is not True:
                raise HostTimezoneError('browser_system_identity_unverified')
        api = WindowsTimezoneReader() if reader is None else reader
        sessions = tuple(api.session_id(identity['pid']) for identity in expected)
        if any(type(value) is not int or not 0 <= value < 0xffffffff for value in sessions):
            raise HostTimezoneError('browser_system_session_unavailable')
        if len(set(sessions)) != 1:
            raise HostTimezoneError('browser_system_session_mismatch')
        observation = api.read_timezone()  # A new API call on every invocation.
        if not _eastern(observation):
            raise HostTimezoneError('browser_system_timezone_not_eastern')
        for identity in expected:
            actual = identify(identity['pid'])
            if not _valid_identity(actual) or same_identity(identity, actual) is not True:
                raise HostTimezoneError('browser_system_identity_unverified')
        return {'source': 'win32_dynamic_timezone_v1', 'timezone': 'Eastern Standard Time',
                'session_verified': True}
    except HostTimezoneError:
        raise
    except Exception:
        raise HostTimezoneError('browser_system_timezone_unavailable') from None
