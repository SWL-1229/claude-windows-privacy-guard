"""One-click, session-scoped Claude Desktop environment launcher.

Uses the already installed IP/DNS/WFP protections and the separately reviewed,
hash-bound DevToolsUi helper.  Does not patch Claude, clear login data, grant an
unrestricted network route, or claim a persistent environment lease.

The transaction is deliberately separate from production guard.py.  --diagnose
is read-only.  --apply performs the transaction; --gui implies --apply and only
shows a short error dialog when intervention is needed.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import queue
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid


SOURCE = Path(__file__).absolute()
ROOT = SOURCE.parent.parent
HERE = SOURCE.parent
HOLD_PURPOSE = 'claude-native-oneclick'
HOLD_SCHEMA = 1
EXPECTED_GATE = ('127.0.0.1', 17894)
EXPECTED_CORE = ('127.0.0.1', 17895)
EXPECTED_ORIGIN = 'https://claude.ai'
CREATE_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
NATIVE_MONITOR_SWITCH = '--disable-backgrounding-occluded-windows'
HELPER_FOREGROUND_FLAG = '--foreground-grant-v2'
HELPER_FOREGROUND_PROTOCOL = 'claude-foreground-grant-v2'
HELPER_FOREGROUND_GO = 'CLAUDE_FOREGROUND_GRANTED_V2\n'
HELPER_FOREGROUND_ALREADY = 'CLAUDE_ALREADY_TARGET_FOREGROUND_V2\n'
HELPER_FOREGROUND_COMMANDS = frozenset(('configure','verify','disable-js','enable-js',
                                      'reload','show','arm-live','main-inspector','main-inspector-close'))
HELD_EXIT_PREFLIGHT_SOURCES = ('cloudflare_trace', 'ipify_json', 'cloudflare_trace')
HELD_EXIT_PREFLIGHT_BUDGET = 20.0
HELD_EXIT_ATTEMPT_BUDGET = 6.0


MESSAGES = {
    'native_rtc_restart_required': '当前 Claude 会话未通过原生 WebRTC 保护验证。请保存工作并从 Claude 托盘完整退出，再点安全入口冷启动；登录资料会保留。',
    'native_rtc_setup_failed': '原生 WebRTC 保护未完成验证，已停止本次启动并保持网络限制。',
    'native_rtc_inspector_cleanup_failed': '临时调试端口未能确认关闭，已停止本次启动并保持网络限制。',
    'another_launcher_running': '另一个 Claude 一键启动正在进行，请稍候。',
    'foreign_hold': '检测到不是本启动器持有的离线锁，已保留原锁并停止。',
    'hold_owner_still_alive': '上一次启动器仍在运行，已停止重复操作。',
    'hold_owner_unknown': '无法安全确认离线锁的所有者状态，已保留锁并停止。',
    'package_changed': 'Claude 版本或安装位置已经变化，请先刷新现有联网保护。',
    'unsafe_existing_process': 'Claude 已在不符合安全参数的旧进程中运行。请保存工作，从 Claude 菜单完整退出后重试。',
    'ambiguous_main_process': '无法唯一确认 Claude 主进程，已停止操作。',
    'helper_manifest_missing': '一键启动组件尚未完成安装，缺少经过核验的组件清单。',
    'helper_hash_mismatch': '开发工具组件校验失败，已停止启动。',
    'helper_failed': '无法完成内置开发工具操作，已按失败关闭处理。',
    'helper_ready_not_confirmed': '启动组件尚未完成窗口授权握手，已停止本次配置并保持保护。',
    'helper_foreground_denied': 'Windows 未授予本次窗口操作权限，已停止配置并保持保护。',
    'helper_continue_cancelled': '没有完成窗口继续操作，已停止本次配置并保持网络限制。',
    'console_paste_required': 'Claude 开发工具需要你亲手解除防误粘贴提示，本次没有自动绕过它。',
    'wrong_timezone': 'Claude 没有读到美东时区，已停止放行。',
    'wrong_language': 'Claude 没有读到英语环境，已停止放行。',
    'wrong_dst_offsets': 'Claude 的冬夏令时偏移不正确，已停止放行。',
    'wrong_origin': '尚未确认真实 Claude 页面，已停止放行。',
    'stale_metadata': '环境检查结果不够新，已停止放行。',
    'environment_monitor_not_ready': '后台环境监控未完成验证，Claude 保持断网；请从安全入口重试。',
    'wrong_frame': '开发工具没有读取到 Claude 顶层页面，已停止放行。',
    'existing_error_page': '已有 Claude 会话当前是错误页。已保留工作和离线锁；请保存工作并完整退出 Claude，再点此入口重试。',
    'exit_not_allowed': '实际出口没有通过指定 IP 校验，Claude 保持断网。',
    'exit_verification_unavailable': '未能及时取得住宅出口校验结果，Claude 保持断网；没有改用其他出口。',
    'service_identity_mismatch': '本地代理或 DNS 监听者身份不符，已停止启动。',
    'ingress_follower_not_ready': '链式入口同步尚未完成验证，Claude 保持断网；请确认 Clash 当前链式出口仍为指定家宽。',
    'services_not_ready': '本地联网保护或定向 DNS 未准备好，已停止启动。',
    'new_main_not_found': '没有及时找到本次启动的 Claude 主进程，已保持失败关闭。',
    'rollback_exit_not_confirmed': '未能确认 Claude 已正常退出，离线锁已保留；请保存工作并完整退出后重试。',
    'invalid_path': '安装路径存在重定向、越界或无法核实的文件，已停止启动。',
    'unexpected_failure': '一键配置没有完成，已按失败关闭处理。详细状态保存在本机。',
}


class LaunchError(RuntimeError):
    def __init__(self, code: str):
        self.code = code if code in MESSAGES else 'unexpected_failure'
        super().__init__(self.code)


class HeldExitPolicyFailure(Exception):
    """Only locally selected closed-enum failure codes, never response data."""
    def __init__(self, reason):
        self.reason = reason if reason in ('outside_allowlist', 'allowlist_changed', 'http_status', 'source_invalid') else 'internal_error'
        super().__init__(self.reason)


class HeldExitAttemptFailure(Exception):
    def __init__(self, diagnostic):
        self.diagnostic = dict(diagnostic)
        super().__init__('held_exit_attempt_failed')


def held_exit_error(error):
    """Transport absence only is retryable; security/content errors are final."""
    if isinstance(error, HeldExitPolicyFailure):return error.reason, False
    if isinstance(error, ssl.SSLCertVerificationError):return 'certificate_error', False
    if isinstance(error, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):return 'tls_eof', True
    if isinstance(error, ssl.SSLError):return 'tls_error', False
    if isinstance(error, TimeoutError):return 'timeout', True
    if isinstance(error, ConnectionError):return 'connection_error', True
    if isinstance(error, http.client.RemoteDisconnected):return 'remote_closed', True
    if isinstance(error, (ValueError, UnicodeError, KeyError)):return 'schema_error', False
    return 'internal_error', False


def one_held_fixed_exit_attempt(guard, source, budget, *, clock=time.monotonic):
    """Fresh read-only TLS measurement over CORE; never grants gate permission."""
    targets={'cloudflare_trace':('www.cloudflare.com','/cdn-cgi/trace','text/plain'),
             'ipify_json':('api.ipify.org','/?format=json','application/json')}
    began=clock();stage='setup';connection=response=None
    diagnostic={'source':source if source in targets else 'unknown','stage':stage,
                'result':'failed','error_type':'internal_error','retryable':False}
    timer=None;expired=threading.Event();active_socket=[None]
    try:
        if source not in targets:raise HeldExitPolicyFailure('source_invalid')
        if type(budget) not in (int,float) or not math.isfinite(budget) or not 0<budget<=HELD_EXIT_ATTEMPT_BUDGET:
            raise ValueError('invalid fixed probe budget')
        deadline=began+budget;allowed=guard.configured_allowlist()
        host,path,accept=targets[source]
        # This retained-response socket type and closed body parser are already
        # used by the production gate; do not call its permission-bearing probe.
        connection=guard._FixedProbeHTTPSConnection(*EXPECTED_CORE,timeout=budget,
                                                    context=ssl.create_default_context())
        connection.set_tunnel(host,443)
        def abort():
            expired.set();sock=connection.sock or active_socket[0]
            if sock is not None:
                try:sock.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                try:sock.close()
                except OSError:pass
        def phase():
            remaining=deadline-clock()
            if remaining>budget:raise ValueError('fixed preflight clock invalid')
            if expired.is_set() or remaining<=0:raise TimeoutError('fixed preflight expired')
            connection.timeout=remaining
            if connection.sock is not None:
                active_socket[0]=connection.sock;connection.sock.settimeout(remaining)
            elif active_socket[0] is not None:active_socket[0].settimeout(remaining)
        timer=threading.Timer(max(0.,deadline-clock()),abort);timer.daemon=True;timer.start()
        stage='connect_tls';phase();connection.connect();phase()
        stage='request';connection.request('GET',path,headers={
            'Host':host,'Accept':accept,'Connection':'close',
            'User-Agent':'ClaudeLocalEnvironmentPreflight/2'})
        stage='response_headers';phase();connection._retain_response_socket=True
        response=connection.getresponse()
        if response.status!=200:raise HeldExitPolicyFailure('http_status')
        phase()
        stage='response_body';body=bytearray()
        while len(body)<=8192:
            phase();chunk=response.read1(min(1024,8193-len(body)))
            if not chunk:break
            body.extend(chunk)
        phase();stage='parse_body'
        actual=guard.parse_fixed_exit_body(source,bytes(body))
        stage='exit_policy'
        after=guard.configured_allowlist()
        if allowed!=after:raise HeldExitPolicyFailure('allowlist_changed')
        if actual not in allowed:raise HeldExitPolicyFailure('outside_allowlist')
        phase()
        diagnostic.update(stage='complete',result='verified',error_type=None,retryable=False,
                          seconds=round(clock()-began,3))
        return actual,diagnostic
    except Exception as error:
        if (not isinstance(error,(HeldExitPolicyFailure,ssl.SSLError,ValueError,UnicodeError,KeyError))
                and (expired.is_set() or clock()>=deadline)
                and isinstance(error,(OSError,http.client.RemoteDisconnected,http.client.IncompleteRead))):
            # Our exact deadline shutdown can surface as BadFD/closed socket
            # instead of TimeoutError. This is absent transport evidence only;
            # it must never turn a certificate/TLS/content/policy failure into
            # a retryable result.
            kind,retryable='timeout',True
        else:kind,retryable=held_exit_error(error)
        diagnostic.update(stage=stage,error_type=kind,retryable=retryable,
                          seconds=round(max(0.,clock()-began),3))
        raise HeldExitAttemptFailure(diagnostic) from None
    finally:
        if timer is not None:timer.cancel()
        if response is not None:
            try:response.close()
            except OSError:pass
        if connection is not None:
            connection._retain_response_socket=False
            try:connection.close()
            except OSError:pass


def canonical(path):
    return os.path.normcase(os.path.abspath(str(path)))


def same_path(left, right):
    return canonical(left) == canonical(right)


def monitor_launch_arguments(command):
    """Copy only the already identified Claude main argv; no caller flags."""
    result = list(command)
    end = result.index('--') if '--' in result else len(result)
    found = [arg for arg in result[1:end]
             if isinstance(arg,str) and arg.partition('=')[0].casefold()==NATIVE_MONITOR_SWITCH]
    if found and found != [NATIVE_MONITOR_SWITCH]:
        raise LaunchError('unsafe_existing_process')
    if not found:
        result.insert(end,NATIVE_MONITOR_SWITCH)
    return result


def physical_path(path: Path, *, boundary: Path | None = None, allow_missing=False):
    """Reject traversal and reparse points without silently following a junction."""
    path = Path(path).absolute()
    if boundary is not None:
        try:
            common = os.path.commonpath([canonical(path), canonical(boundary)])
        except ValueError:
            raise LaunchError('invalid_path') from None
        if common != canonical(boundary):
            raise LaunchError('invalid_path')
    if not same_path(path, path.resolve(strict=False)):
        raise LaunchError('invalid_path')
    for current in [path, *path.parents]:
        try:
            info = current.lstat()
        except FileNotFoundError:
            if current == path and allow_missing:
                continue
            raise LaunchError('invalid_path') from None
        except OSError:
            raise LaunchError('invalid_path') from None
        if current.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise LaunchError('invalid_path')
    return path


def small_json(path: Path, *, boundary: Path, max_bytes=65536):
    path = physical_path(path, boundary=boundary)
    try:
        if path.stat().st_size > max_bytes:
            raise ValueError('too large')
        result = json.loads(path.read_text(encoding='utf-8-sig'))
        if not isinstance(result, dict):
            raise ValueError('not an object')
        return result
    except (OSError, ValueError, UnicodeError):
        raise LaunchError('invalid_path') from None


def ci_get(obj, name, default=None):
    if not isinstance(obj, dict):
        return default
    return next((v for k, v in obj.items() if str(k).casefold() == name.casefold()), default)


def metadata(data, *, real_origin, now=None):
    """Keep only approved, account-free, freshly read runtime metadata."""
    now = time.time() if now is None else now
    if isinstance(ci_get(data, 'metadata'), dict):
        data = ci_get(data, 'metadata')
    zone = ci_get(data, 'timeZone')
    language = ci_get(data, 'language')
    january = ci_get(data, 'januaryOffset')
    july = ci_get(data, 'julyOffset')
    origin = ci_get(data, 'origin')
    nonce = ci_get(data, 'nonce')
    epoch = ci_get(data, 'epoch')
    top_frame = ci_get(data, 'topFrame')
    if zone != 'America/New_York':
        raise LaunchError('wrong_timezone')
    if language != 'en-US':
        raise LaunchError('wrong_language')
    if (type(january) not in (int, float) or type(july) not in (int, float)
            or january != 300 or july != 240):
        raise LaunchError('wrong_dst_offsets')
    if not isinstance(nonce, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,96}', nonce):
        raise LaunchError('stale_metadata')
    if (type(epoch) not in (int, float) or not math.isfinite(epoch)
            or abs(epoch / 1000 - now) > 20):
        raise LaunchError('stale_metadata')
    if top_frame is not True:
        raise LaunchError('wrong_frame')
    permitted_origins = {EXPECTED_ORIGIN} if real_origin else {
        EXPECTED_ORIGIN, 'null', 'chrome-error://chromewebdata',
        'chrome-error://chromewebdata/', 'about:blank',
    }
    if origin not in permitted_origins:
        raise LaunchError('wrong_origin')
    # Never retain href, console output, conversation IDs, or extra helper data.
    return dict(origin=origin, timeZone=zone, language=language,
                januaryOffset=january, julyOffset=july, epoch=epoch, nonce=nonce, topFrame=True)


def safe_error(exc):
    return exc.code if isinstance(exc, LaunchError) else 'unexpected_failure'


def helper_ready_reply(command, identity, helper_pid, raw):
    """Exact fixed readiness only; never a child-supplied command or payload."""
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:
                raise ValueError('duplicate ready key')
            value[key]=item
        return value
    try:
        if isinstance(raw,str) and raw.startswith('\ufeff'):
            raw=raw[1:]  # Optional BOM belongs only to the first stdout line.
        if (not isinstance(raw,str) or len(raw)>2048 or not raw.endswith('\n')
                or raw.count('\n')!=1):
            raise ValueError()
        value=json.loads(raw,object_pairs_hook=unique)
        if (not isinstance(value,dict)
                or set(value)!={'protocol','ready','command','pid','helperPid','targetCreation',
                                'exactTargetDevToolsAlreadyForeground'}
                or value.get('protocol')!=HELPER_FOREGROUND_PROTOCOL or value.get('ready') is not True
                or value.get('command')!=command or type(value.get('pid')) is not int
                or value['pid']!=identity['pid'] or type(value.get('helperPid')) is not int
                or value['helperPid']!=helper_pid or value.get('targetCreation')!=identity['creation']
                or type(value.get('exactTargetDevToolsAlreadyForeground')) is not bool):
            raise ValueError()
        return value['exactTargetDevToolsAlreadyForeground']
    except (ValueError,TypeError,KeyError):
        raise LaunchError('helper_ready_not_confirmed') from None


def wait_helper_ready(process, command, identity):
    # Windows anonymous pipes are not selectable. This one bounded daemon read
    # consumes only the first <=2048-character readiness line, never UI output.
    messages=queue.Queue(maxsize=1)
    def read():
        try:
            raw=process.stdout.readline(2049)
        except Exception:
            raw=None
        messages.put(raw)
    threading.Thread(target=read,name='ClaudeHelperReady',daemon=True).start()
    try:
        raw=messages.get(timeout=5)
    except queue.Empty:
        raise LaunchError('helper_ready_not_confirmed') from None
    return helper_ready_reply(command,identity,process.pid,raw)


def activation_failure_metadata(value):
    """Optional exact Win32 diagnostics from the reviewed helper, no titles."""
    window_keys={'exists','visible','minimized','enabled','disabledStyle','noActivateStyle',
                 'topmostStyle','ownerPresent','ownerIsTargetProcess','differentLastPopup',
                 'lastPopupVisible','lastPopupIsTargetProcess'}
    foreground_keys={'present','pid','isTargetProcess','isHelperProcess'}
    if (not isinstance(value,dict) or set(value)!={'activationTarget','before','after',
            'foregroundBefore','foregroundAfter','showWindowPreviouslyVisible',
            'setForegroundReturned','elapsedMilliseconds'}
            or value.get('activationTarget') not in ('main','devtools')
            or type(value.get('showWindowPreviouslyVisible')) is not bool
            or type(value.get('setForegroundReturned')) is not bool
            or type(value.get('elapsedMilliseconds')) is not int
            or not 0<=value['elapsedMilliseconds']<=60000):
        return None
    for name in ('before','after'):
        part=value.get(name)
        if not isinstance(part,dict) or set(part)!=window_keys or any(type(v) is not bool for v in part.values()):
            return None
    for name in ('foregroundBefore','foregroundAfter'):
        part=value.get(name)
        if (not isinstance(part,dict) or set(part)!=foreground_keys
                or any(type(part.get(k)) is not bool for k in ('present','isTargetProcess','isHelperProcess'))
                or type(part.get('pid')) is not int or not 0<=part['pid']<=0xffffffff):
            return None
    return json.loads(json.dumps(value))


def native_inspector_ack(command, value):
    """A menu acknowledgement is not a socket ownership proof."""
    target_enabled = command == 'main-inspector'
    before = ci_get(value, 'stateBefore')
    invoked = ci_get(value, 'invoked')
    if (ci_get(value, 'source') != 'official_developer_menu'
            or before not in ('off','on') or type(invoked) is not bool
            or ci_get(value, 'targetEnabled') is not target_enabled
            or ci_get(value, 'alreadyEnabled') is not (before == 'on')
            or ci_get(value, 'toggleRequested') is not invoked
            or ci_get(value, 'menuStateConfirmed') is not True
            or ci_get(value, 'stateMechanism') not in ('uia-toggle','msaa-checkbox')
            or type(ci_get(value, 'mainHwnd')) is not int or ci_get(value, 'mainHwnd') <= 0
            or invoked is not ((before == 'on') != target_enabled)):
        raise LaunchError('native_rtc_setup_failed')
    return value


def helper_reply(command, pid, returncode, stdout):
    """Validate acknowledgements, not merely a truthy top-level ok field."""
    try:
        if not isinstance(stdout, str) or len(stdout) > 131072:
            raise ValueError('invalid helper output')
        obj = json.loads(stdout)
        if ci_get(obj, 'ok') is not True or returncode != 0:
            code = ci_get(obj, 'error')
            if isinstance(code, dict):
                code = ci_get(code, 'code')
            normalized = re.sub(r'[^a-z]', '', str(code).casefold())
            if normalized in {'consolepasterequired', 'selfxsswarning', 'pastewarning'}:
                raise LaunchError('console_paste_required')
            raise LaunchError('helper_failed')
        reply_command, reply_pid = ci_get(obj, 'command'), ci_get(obj, 'pid')
        if (not isinstance(reply_command, str) or reply_command.casefold() != command
                or type(reply_pid) is not int or reply_pid != pid):
            raise LaunchError('helper_failed')
        data = ci_get(obj, 'data')
        if not isinstance(data, dict) or not data:
            raise LaunchError('helper_failed')
        expected = {
            'disable-js': ('javascriptDisabled', True),
            'enable-js': ('javascriptDisabled', False),
            'configure': ('configured', True),
            'reload': ('reloadRequested', True),
            'hide': ('hidden', True),
            'park-monitor': ('parked', True),
            'park-monitor-bottom': ('parked', True),
        }
        if command in expected:
            field, value = expected[command]
            if ci_get(data, field) is not value:
                raise LaunchError('helper_failed')
        if command in ('main-inspector','main-inspector-close'):
            native_inspector_ack(command, data)
        return data
    except LaunchError:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise LaunchError('helper_failed') from None


class ExclusiveFile:
    """Windows handle prevents replacement while owned; crash leaves hold on disk.

    Deliberately NO FILE_FLAG_DELETE_ON_CLOSE: a controller crash must not remove
    an offline hold. Normal success deletes the exact opened file by handle.
    """
    def __init__(self, path: Path, *, create):
        if os.name != 'nt':
            raise LaunchError('invalid_path')
        self.path, self.handle = path, None
        k = C.WinDLL('kernel32', use_last_error=True)
        k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p,
                                  W.DWORD, W.DWORD, W.HANDLE]
        k.CreateFileW.restype = W.HANDLE
        k.ReadFile.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
        k.WriteFile.argtypes = [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p]
        k.SetFilePointerEx.argtypes = [W.HANDLE, C.c_longlong, C.c_void_p, W.DWORD]
        k.SetEndOfFile.argtypes = [W.HANDLE]
        k.GetFileSizeEx.argtypes = [W.HANDLE, C.POINTER(C.c_longlong)]
        k.FlushFileBuffers.argtypes = [W.HANDLE]
        k.SetFileInformationByHandle.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD]
        k.CloseHandle.argtypes = [W.HANDLE]
        self.kernel = k
        # GENERIC_READ | GENERIC_WRITE | DELETE, share READ only.
        value = k.CreateFileW(str(path), 0xC0010000, 1, None,
                             1 if create else 3, 0x00200000, None)
        if value == W.HANDLE(-1).value:
            error = C.get_last_error()
            if create and error in (80, 183):
                raise FileExistsError(str(path))
            if not create and error in (2, 3):
                raise FileNotFoundError(str(path))
            raise LaunchError('hold_owner_unknown')
        self.handle = value

    def read(self):
        length = C.c_longlong()
        if not self.kernel.GetFileSizeEx(self.handle, C.byref(length)) or not 0 < length.value <= 8192:
            raise LaunchError('foreign_hold')
        if not self.kernel.SetFilePointerEx(self.handle, 0, None, 0):
            raise LaunchError('hold_owner_unknown')
        buffer, count = C.create_string_buffer(length.value), W.DWORD()
        if not self.kernel.ReadFile(self.handle, buffer, length.value, C.byref(count), None):
            raise LaunchError('hold_owner_unknown')
        try:
            value = json.loads(buffer.raw[:count.value].decode('utf-8'))
        except (ValueError, UnicodeError):
            raise LaunchError('foreign_hold') from None
        if not isinstance(value, dict):
            raise LaunchError('foreign_hold')
        return value

    def write(self, value):
        data = (json.dumps(value, separators=(',', ':')) + '\n').encode('utf-8')
        if len(data) > 8192 or not self.kernel.SetFilePointerEx(self.handle, 0, None, 0):
            raise LaunchError('hold_owner_unknown')
        count, buffer = W.DWORD(), C.create_string_buffer(data)
        if not self.kernel.WriteFile(self.handle, buffer, len(data), C.byref(count), None) or count.value != len(data):
            raise LaunchError('hold_owner_unknown')
        if not self.kernel.SetEndOfFile(self.handle) or not self.kernel.FlushFileBuffers(self.handle):
            raise LaunchError('hold_owner_unknown')

    def delete(self):
        # FileDispositionInfo: delete this exact, exclusively opened file.
        flag = C.c_ubyte(1)  # FILE_DISPOSITION_INFO.DeleteFile is BOOLEAN.
        if not self.kernel.SetFileInformationByHandle(self.handle, 4, C.byref(flag), C.sizeof(flag)):
            raise LaunchError('hold_owner_unknown')
        self.close()

    def close(self):
        if self.handle is not None:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class OwnedHold:
    def __init__(self, root, owner, alive, *, open_file=ExclusiveFile, validate=physical_path,
                 allowed_owner_images=None):
        self.root, self.owner, self.alive = Path(root), dict(owner), alive
        self.path = self.root / 'hold.block'
        self.open_file, self.validate = open_file, validate
        self.allowed_owner_images = {canonical(p) for p in (allowed_owner_images or [owner['image']])}
        self.launcher = canonical(self.root / 'native-launcher/native_desktop_launch.py')
        self.file = None
        self.nonce = uuid.uuid4().hex
        self.recovered = False

    @property
    def owned(self):
        return self.file is not None

    def value(self):
        return dict(schema_version=HOLD_SCHEMA, purpose=HOLD_PURPOSE,
                    root=canonical(self.root), launcher=self.launcher, owner_nonce=self.nonce,
                    owner_pid=self.owner['pid'], owner_creation=self.owner['creation'],
                    owner_image=canonical(self.owner['image']), created_at=time.time())

    def recover_existing(self):
        self.validate(self.path, boundary=self.root, allow_missing=True)
        try:
            handle = self.open_file(self.path, create=False)
        except FileNotFoundError:
            return False
        try:
            value = handle.read()
            if (value.get('schema_version') != HOLD_SCHEMA or value.get('purpose') != HOLD_PURPOSE
                    or value.get('root') != canonical(self.root)
                    or value.get('launcher') != self.launcher
                    or not re.fullmatch(r'[0-9a-f]{32}', str(value.get('owner_nonce', '')))
                    or type(value.get('owner_pid')) is not int or value['owner_pid'] <= 0
                    or not re.fullmatch(r'[0-9a-f]{16}', str(value.get('owner_creation', '')))
                    or canonical(value.get('owner_image', '')) not in self.allowed_owner_images):
                raise LaunchError('foreign_hold')
            life = self.alive(dict(pid=value['owner_pid'], creation=value['owner_creation'],
                                   image=value['owner_image']))
            if life is True:
                raise LaunchError('hold_owner_still_alive')
            if life is not False:
                raise LaunchError('hold_owner_unknown')
            # Adopt in place. There is never a delete/re-create admission gap.
            handle.write(self.value())
            self.file, self.recovered = handle, True
            return True
        except Exception:
            handle.close()
            raise

    def acquire(self):
        if self.owned:
            return
        self.validate(self.path, boundary=self.root, allow_missing=True)
        try:
            handle = self.open_file(self.path, create=True)
        except FileExistsError:
            raise LaunchError('foreign_hold') from None
        try:
            handle.write(self.value())
            self.file = handle
        except Exception:
            # An incomplete file remains a fail-closed hold, never delete blind.
            handle.close()
            raise

    def release(self):
        if not self.owned:
            return
        current = self.file.read()
        if (current.get('owner_nonce') != self.nonce or current.get('purpose') != HOLD_PURPOSE
                or current.get('owner_pid') != self.owner['pid']):
            raise LaunchError('foreign_hold')
        self.file.delete()
        self.file = None

    def close_preserving(self):
        if self.file is not None:
            self.file.close()
            self.file = None


class SingleInstance:
    def __init__(self, root, scope='transaction'):
        self.root, self.handle, self.acquired = root, None, False
        if scope not in ('transaction', 'gui'):
            raise LaunchError('unexpected_failure')
        self.scope = scope

    def __enter__(self):
        k = C.WinDLL('kernel32', use_last_error=True)
        k.CreateMutexW.argtypes = [C.c_void_p, W.BOOL, W.LPCWSTR]
        k.CreateMutexW.restype = W.HANDLE
        k.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
        k.ReleaseMutex.argtypes = [W.HANDLE]
        k.CloseHandle.argtypes = [W.HANDLE]
        self.kernel = k
        # Local session plus physical, per-user installation path.
        prefix = 'Local\\ClaudeNativeOneClick-UI-' if self.scope == 'gui' else 'Local\\ClaudeNativeOneClick-'
        name = prefix + hashlib.sha256(canonical(self.root).encode()).hexdigest()[:24]
        self.handle = k.CreateMutexW(None, False, name)
        if not self.handle:
            raise LaunchError('unexpected_failure')
        self.acquired = k.WaitForSingleObject(self.handle, 0) in (0, 0x80)
        return self

    def __exit__(self, *_):
        if self.handle:
            if self.acquired:
                self.kernel.ReleaseMutex(self.handle)
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class WindowsBackend:
    def __init__(self, root=ROOT):
        self.root = physical_path(Path(root))
        self.here = physical_path(self.root / 'native-launcher', boundary=self.root)
        physical_path(SOURCE, boundary=self.root)
        guard_path = physical_path(self.root / 'guard.py', boundary=self.root)
        spec = importlib.util.spec_from_file_location('claude_native_launch_existing_guard', guard_path)
        self.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.guard)
        if tuple(self.guard.LISTEN) != EXPECTED_GATE or tuple(self.guard.CORE_PROXY) != EXPECTED_CORE:
            raise LaunchError('invalid_path')
        self.installed = small_json(self.root / 'installed.json', boundary=self.root)
        runtime = small_json(self.root / 'environment-runtime.json', boundary=self.root)
        self.python = physical_path(Path(runtime['python_executable']))
        self.pythonw = physical_path(self.python.with_name('pythonw.exe'))
        self.runtime = small_json(self.root / 'runtime.json', boundary=self.root)
        self.package = self.candidate = None
        self._helper = self._helper_hash = None
        self.helper_failures = []
        self.helper_foreground_grants = []
        self._rtc_nonce = uuid.uuid4().hex
        self._rtc_module = None

    def mutex(self):
        return SingleInstance(self.root)

    def now(self):
        return time.time()

    def sleep(self, seconds):
        time.sleep(seconds)

    def powershell(self, script, timeout=12):
        prefix = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); "
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', prefix + script],
                                capture_output=True, text=True, encoding='utf-8-sig', timeout=timeout,
                                creationflags=CREATE_NO_WINDOW)
        if result.returncode or len(result.stdout) > 1048576:
            raise LaunchError('unexpected_failure')
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise LaunchError('unexpected_failure') from None

    def preflight(self):
        obj = self.powershell("Get-AppxPackage -Name Claude | Sort-Object Version -Descending | Select-Object -First 1 PackageFullName,PackageFamilyName,InstallLocation | ConvertTo-Json -Compress")
        if not isinstance(obj, dict) or obj.get('PackageFullName') != self.installed.get('package'):
            raise LaunchError('package_changed')
        package_dir = Path(obj['InstallLocation'])
        if (not same_path(package_dir.parent, self.runtime['package_parent'])
                or package_dir.name != self.installed.get('package')
                or obj.get('PackageFamilyName') != self.installed.get('family')
                or self.installed.get('verified') is not True):
            raise LaunchError('package_changed')
        self.candidate = physical_path(package_dir / 'app/Claude.exe', boundary=package_dir)
        self.package = obj['PackageFullName']
        rows = self.guard.claude_process_snapshot()
        try:
            self.strict_launch_preflight(rows=rows)
        except Exception:
            raise LaunchError('unsafe_existing_process') from None
        main = self.find_main(rows)
        # Validate the reviewed helper before starting any transaction.
        self.helper_path()
        return main

    def strict_launch_preflight(self, rows):
        # Preserve all seven reviewed proxy/privacy requirements unchanged.
        # This additional check applies only to main processes in the exact
        # installed image, never to known children or unrelated applications.
        self.guard.existing_claude_launch_preflight(self.candidate,rows=rows)
        for row in rows:
            if not same_path(row.get('ExecutablePath',''),self.candidate):
                continue
            argv=self.guard.windows_command_line_args(row.get('CommandLine'))[1:]
            if '--' in argv:
                argv=argv[:argv.index('--')]
            if any(arg.partition('=')[0].casefold()=='--type' for arg in argv):
                continue  # The original strict validator already checked type.
            found=[arg for arg in argv if arg.partition('=')[0].casefold()==NATIVE_MONITOR_SWITCH]
            if found != [NATIVE_MONITOR_SWITCH]:
                raise LaunchError('unsafe_existing_process')

    def find_main(self, rows=None):
        rows = self.guard.claude_process_snapshot() if rows is None else rows
        mains = []
        for row in rows:
            if not same_path(row.get('ExecutablePath', ''), self.candidate):
                continue
            argv = self.guard.windows_command_line_args(row.get('CommandLine'))[1:]
            if '--' in argv:
                argv = argv[:argv.index('--')]
            if not any(a.partition('=')[0].casefold() == '--type' for a in argv):
                mains.append(row['ProcessId'])
        if len(mains) > 1:
            raise LaunchError('ambiguous_main_process')
        if not mains:
            return None
        identity = self.identity(mains[0])
        if not identity or not same_path(identity['image'], self.candidate):
            raise LaunchError('ambiguous_main_process')
        return identity

    def identity(self, pid):
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
            raise LaunchError('hold_owner_unknown')
        try:
            status = W.DWORD()
            if not k.GetExitCodeProcess(handle, C.byref(status)):
                raise LaunchError('hold_owner_unknown')
            if status.value != 259:
                return None
            creation, exited, kernel, user = [W.FILETIME() for _ in range(4)]
            image, size = C.create_unicode_buffer(32768), W.DWORD(32768)
            if (not k.GetProcessTimes(handle, C.byref(creation), C.byref(exited), C.byref(kernel), C.byref(user))
                    or not k.QueryFullProcessImageNameW(handle, 0, image, C.byref(size))):
                raise LaunchError('hold_owner_unknown')
            stamp = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
            return dict(pid=int(pid), creation=f'{stamp:016x}', image=canonical(image.value))
        finally:
            k.CloseHandle(handle)

    def alive(self, identity):
        try:
            current = self.identity(identity['pid'])
        except LaunchError:
            return None
        return bool(current and current['creation'] == identity['creation']
                    and same_path(current['image'], identity['image']))

    def hold(self):
        owner = self.identity(os.getpid())
        if owner is None:
            raise LaunchError('hold_owner_unknown')
        return OwnedHold(self.root, owner, self.alive,
                         allowed_owner_images=[self.python, self.pythonw])

    def helper_path(self):
        manifest_path = self.here / 'helper-manifest.json'
        if not manifest_path.exists():
            raise LaunchError('helper_manifest_missing')
        manifest = small_json(manifest_path, boundary=self.here)
        name, digest = manifest.get('helper_executable'), manifest.get('sha256')
        if (manifest.get('schema_version') != 1 or name != 'DevToolsUi.exe'
                or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', digest)):
            raise LaunchError('helper_hash_mismatch')
        path = physical_path(self.here / name, boundary=self.here)
        if path.stat().st_size > 16777216 or hashlib.sha256(path.read_bytes()).hexdigest() != digest.casefold():
            raise LaunchError('helper_hash_mismatch')
        self._helper, self._helper_hash = path, digest.casefold()
        return path

    def helper(self, command, identity, monitor_nonce=None, previous_nonce=None):
        if command not in {'inspect', 'configure', 'verify', 'disable-js', 'enable-js', 'reload', 'hide', 'show', 'arm-live', 'park-monitor', 'park-monitor-bottom', 'main-inspector', 'main-inspector-close'}:
            raise LaunchError('helper_failed')
        extra = []
        if command == 'arm-live':
            if not isinstance(monitor_nonce, str) or not re.fullmatch('[0-9a-f]{32}', monitor_nonce):
                raise LaunchError('helper_failed')
            extra = [monitor_nonce]
            if previous_nonce is not None:
                if not isinstance(previous_nonce, str) or not re.fullmatch('[0-9a-f]{32}', previous_nonce):
                    raise LaunchError('helper_failed')
                extra.append(previous_nonce)
        elif monitor_nonce is not None:
            raise LaunchError('helper_failed')
        if command != 'arm-live' and previous_nonce is not None:
            raise LaunchError('helper_failed')
        if self.alive(identity) is not True:
            raise LaunchError('helper_failed')
        path = self.helper_path()  # Reject component changes between commands.
        process = None
        handshake = command in HELPER_FOREGROUND_COMMANDS
        grant_record = None
        try:
            argv=[str(path),command,str(identity['pid']),identity['creation']]+extra
            if handshake:
                argv.append(HELPER_FOREGROUND_FLAG)
            process = subprocess.Popen(argv,
                                       stdin=subprocess.PIPE if handshake else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, encoding='utf-8' if handshake else 'utf-8-sig',
                                       errors='strict', creationflags=CREATE_NO_WINDOW)
            if handshake:
                grant_record={'command':command,'helper_pid':process.pid,'ready_confirmed':False,
                              'grant_attempted':False,'grant_succeeded':None,
                              'foreground_owner_matches_parent':None,'win32_error':None}
                self.helper_foreground_grants=getattr(self,'helper_foreground_grants',[])+[grant_record]
                self.helper_foreground_grants=self.helper_foreground_grants[-16:]
                already_foreground=wait_helper_ready(process,command,identity)
                if process.poll() is not None:
                    raise LaunchError('helper_ready_not_confirmed')
                grant_record['ready_confirmed']=True
                grant_record['exact_target_already_foreground']=already_foreground
                grant_record['grant_attempted']=True
                granted=self.authorize_helper_foreground(process.pid)
                grant_record['grant_succeeded']=granted is True
                detail=getattr(self,'_last_foreground_grant',{})
                if type(detail.get('foreground_owner_matches_parent')) is bool:
                    grant_record['foreground_owner_matches_parent']=detail['foreground_owner_matches_parent']
                if type(detail.get('win32_error')) is int and 0<=detail['win32_error']<=0xffffffff:
                    grant_record['win32_error']=detail['win32_error']
                if granted is not True and already_foreground is not True:
                    retry=getattr(self,'foreground_retry',None)
                    if not callable(retry):
                        raise LaunchError('helper_foreground_denied')
                    # No GO was sent. Reap the denied helper before asking for
                    # one explicit GUI click. The transaction and hold remain
                    # active; no additional Claude process is launched.
                    denied=process
                    process=None
                    self._close_waiting_helper(denied)
                    self._pending_foreground_command=command
                    try:
                        process=retry(lambda: self._fresh_gui_foreground_helper(command,identity,extra))
                    finally:
                        self._pending_foreground_command=None
                    stdout,_=process.communicate(timeout=35)
                else:
                    token=HELPER_FOREGROUND_GO if granted is True else HELPER_FOREGROUND_ALREADY
                    grant_record['authorization_mode']='os-grant' if granted is True else 'existing-target-foreground'
                    stdout,_=process.communicate(input=token,timeout=35)
            else:
                # Read-only/no-activation commands keep the old interface and
                # do not require foreground privilege for background polling.
                stdout,_=process.communicate(timeout=35)
            # Only diagnostics generated by the hash-bound local component,
            # never raw Console output or surrounding application messages.
            try:
                acknowledgement = json.loads(stdout)
                error = ci_get(acknowledgement, 'error')
                if (ci_get(acknowledgement, 'command') == command
                        and ci_get(acknowledgement, 'pid') == identity['pid']
                        and ci_get(acknowledgement, 'ok') is False
                        and isinstance(error, str)
                        and re.fullmatch(r'[A-Za-z0-9:_ .-]{1,96}', error)):
                    failure = dict(command=command, error=error)
                    details = ci_get(acknowledgement, 'data')
                    if error=='CannotActivateExpectedWindow':
                        activation=activation_failure_metadata(details)
                        if activation is not None:
                            failure['activation_diagnostic']=activation
                    if command == 'arm-live' and isinstance(details, dict):
                        safe = {}
                        for key in ('before', 'after', 'chosenIndex', 'valueLength'):
                            value = ci_get(details, key)
                            if type(value) is int and 0 <= value <= 32768:
                                safe[key] = value
                        for key in ('whitespaceOnly', 'trimmedIsExpression', 'startsWithOwnMetadata'):
                            value = ci_get(details, key)
                            if type(value) is bool:
                                safe[key] = value
                        if safe:
                            failure['live_editor_diagnostic'] = safe
                    self.helper_failures.append(failure)
                    self.helper_failures = self.helper_failures[-8:]
            except (ValueError, TypeError):
                pass
            return helper_reply(command, identity['pid'], process.returncode, stdout)
        except LaunchError:
            raise
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            raise LaunchError('helper_failed') from None
        finally:
            if process is not None and process.poll() is None:
                # Only this launcher-created helper, never the user's app.
                process.kill()
                try:
                    process.communicate(timeout=3)
                except Exception:
                    pass

    @staticmethod
    def _close_waiting_helper(process):
        """Only the launcher-created denied helper, never Claude or its work."""
        try:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)
        finally:
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass

    def _fresh_gui_foreground_helper(self,command,identity,extra):
        """Called ONLY by the explicit Continue callback on the GUI thread.

        Never reuse a previous permission or waiting PID. The reviewed bridge
        enforces GUI thread affinity and one attempt per user click.
        """
        if command not in HELPER_FOREGROUND_COMMANDS or self.alive(identity) is not True:
            raise LaunchError('helper_failed')
        path=self.helper_path()  # Recheck after the potentially long human wait.
        process=None
        transferred=False
        try:
            argv=[str(path),command,str(identity['pid']),identity['creation']]+list(extra)+[HELPER_FOREGROUND_FLAG]
            process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,text=True,encoding='utf-8',
                                     errors='strict',creationflags=CREATE_NO_WINDOW)
            record={'command':command,'helper_pid':process.pid,'ready_confirmed':False,
                    'grant_attempted':False,'grant_succeeded':None,
                    'foreground_owner_matches_parent':None,'win32_error':None,
                    'explicit_user_continue':True}
            self.helper_foreground_grants=getattr(self,'helper_foreground_grants',[])+[record]
            self.helper_foreground_grants=self.helper_foreground_grants[-16:]
            already=wait_helper_ready(process,command,identity)
            if process.poll() is not None or self.alive(identity) is not True:
                raise LaunchError('helper_ready_not_confirmed')
            record['ready_confirmed']=True
            record['exact_target_already_foreground']=already
            record['grant_attempted']=True
            granted=self.authorize_helper_foreground(process.pid)
            record['grant_succeeded']=granted is True
            detail=getattr(self,'_last_foreground_grant',{})
            if type(detail.get('foreground_owner_matches_parent')) is bool:
                record['foreground_owner_matches_parent']=detail['foreground_owner_matches_parent']
            if type(detail.get('win32_error')) is int and 0<=detail['win32_error']<=0xffffffff:
                record['win32_error']=detail['win32_error']
            # The user clicked this GUI, so this branch requires a fresh real
            # OS grant. Do not fall back to a stale window or cached permission.
            if granted is not True:
                raise LaunchError('helper_foreground_denied')
            record['authorization_mode']='explicit-user-os-grant'
            process.stdin.write(HELPER_FOREGROUND_GO)
            process.stdin.flush()
            process.stdin.close()
            process.stdin=None  # communicate must not flush a closed stream.
            transferred=True
            return process
        finally:
            if process is not None and not transferred:
                self._close_waiting_helper(process)

    def authorize_helper_foreground(self, child_pid):
        if type(child_pid) is not int or not 0 < child_pid < 0xFFFFFFFF:
            raise LaunchError('helper_failed')
        user = C.WinDLL('user32', use_last_error=True)
        user.AllowSetForegroundWindow.argtypes = [W.DWORD]
        user.AllowSetForegroundWindow.restype = W.BOOL
        user.GetForegroundWindow.argtypes=[]
        user.GetForegroundWindow.restype=W.HWND
        user.GetWindowThreadProcessId.argtypes=[W.HWND,C.POINTER(W.DWORD)]
        user.GetWindowThreadProcessId.restype=W.DWORD
        owner=W.DWORD()
        user.GetWindowThreadProcessId(user.GetForegroundWindow(),C.byref(owner))
        C.set_last_error(0)
        granted=bool(user.AllowSetForegroundWindow(child_pid))
        self._last_foreground_grant={'foreground_owner_matches_parent':owner.value==os.getpid(),
                                     'win32_error':C.get_last_error()}
        return granted

    def service_snapshot(self):
        script = """$taskTcp=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object LocalPort -in 17894,17895,53 | Select-Object LocalAddress,LocalPort,OwningProcess); $taskUdp=@(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object LocalPort -eq 53 | Select-Object LocalAddress,LocalPort,OwningProcess); $taskPids=@(@($taskTcp.OwningProcess)+@($taskUdp.OwningProcess) | Sort-Object -Unique); $taskProc=@(foreach($taskPid in $taskPids){ Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$taskPid) | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine }); $taskParentPids=@($taskProc.ParentProcessId | Where-Object {$_ -notin $taskPids} | Sort-Object -Unique); $taskParents=@(foreach($taskPid in $taskParentPids){ Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$taskPid) | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine }); [pscustomobject]@{tcp=$taskTcp;udp=$taskUdp;processes=@($taskProc)+@($taskParents)} | ConvertTo-Json -Depth 4 -Compress"""
        result = self.powershell(script)
        if not isinstance(result, dict):
            raise LaunchError('services_not_ready')
        return result

    def expected_script(self, process, script, *, worker=None):
        if not isinstance(process, dict) or not same_path(process.get('ExecutablePath', ''), self.pythonw):
            return False
        try:
            argv = self.guard.windows_command_line_args(process.get('CommandLine'))
        except Exception:
            return False
        if not argv or not same_path(argv[0], self.pythonw):
            return False
        argv = list(argv[1:])
        while argv and argv[0] in ('-I', '-B', '-u'):
            argv.pop(0)
        if not argv or not same_path(argv.pop(0), self.root / script):
            return False
        if script == 'guard.py':
            return argv == ['--serve']
        if worker is False:
            return argv == []
        if worker is True:
            return (len(argv) == 5 and argv[:2] == ['--worker', '--generation']
                    and bool(re.fullmatch(r'[0-9a-f]{32}', argv[2]))
                    and argv[3] == '--supervisor-pid' and argv[4].isdigit()
                    and int(argv[4]) == process.get('ParentProcessId'))
        return True

    def check_services(self, snapshot):
        tcp, udp = snapshot.get('tcp', []), snapshot.get('udp', [])
        processes = {p['ProcessId']: p for p in snapshot.get('processes', [])}
        if not isinstance(tcp, list) or not isinstance(udp, list):
            raise LaunchError('service_identity_mismatch')
        roles = {}
        for port, role in ((17894, 'gate'), (17895, 'core'), (53, 'dns_tcp')):
            listeners = [p for p in tcp if p.get('LocalPort') == port]
            if not listeners:
                roles[role] = None
                continue
            if len(listeners) != 1 or listeners[0].get('LocalAddress') != '127.0.0.1':
                raise LaunchError('service_identity_mismatch')
            roles[role] = processes.get(listeners[0]['OwningProcess'])
            if roles[role] is None:
                raise LaunchError('service_identity_mismatch')
        listeners = [p for p in udp if p.get('LocalPort') == 53]
        if listeners:
            if len(listeners) != 1 or listeners[0].get('LocalAddress') != '127.0.0.1':
                raise LaunchError('service_identity_mismatch')
            roles['dns_udp'] = processes.get(listeners[0]['OwningProcess'])
        else:
            roles['dns_udp'] = None
        gate, core = roles['gate'], roles['core']
        if gate and not self.expected_script(gate, 'guard.py'):
            raise LaunchError('service_identity_mismatch')
        if core and (not gate or core.get('ParentProcessId') != gate['ProcessId']
                     or not same_path(core.get('ExecutablePath', ''), self.runtime['core_executable'])):
            raise LaunchError('service_identity_mismatch')
        for role in ('dns_tcp', 'dns_udp'):
            p = roles[role]
            if p and not self.expected_script(p, 'dns_service.py', worker=True):
                raise LaunchError('service_identity_mismatch')
            if p:
                supervisor = processes.get(p.get('ParentProcessId'))
                if not self.expected_script(supervisor, 'dns_service.py', worker=False):
                    raise LaunchError('service_identity_mismatch')
        if roles['dns_tcp'] and roles['dns_udp'] and roles['dns_tcp']['ProcessId'] != roles['dns_udp']['ProcessId']:
            raise LaunchError('service_identity_mismatch')
        return roles

    def ensure_ingress_follower(self):
        source = physical_path(self.root / 'ingress_follow.py', boundary=self.root)
        spec = importlib.util.spec_from_file_location('claude_native_ingress_preflight', source)
        if spec is None or spec.loader is None:
            raise LaunchError('ingress_follower_not_ready')
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
            return module.ensure_running(self.root)
        except Exception:
            raise LaunchError('ingress_follower_not_ready') from None

    def ensure_services(self):
        deadline, guard_started, dns_started = self.now() + 25, False, False
        while self.now() < deadline:
            roles = self.check_services(self.service_snapshot())
            if all(roles.values()):
                self.ensure_ingress_follower()
                return {k: v['ProcessId'] for k, v in roles.items()}
            if roles['gate'] is None and roles['core'] is None and not guard_started:
                self.guard.start_hidden()
                guard_started = True
            if roles['dns_tcp'] is None and roles['dns_udp'] is None and not dns_started:
                physical_path(self.root / 'dns_service.py', boundary=self.root)
                subprocess.Popen([str(self.pythonw), '-I', str(self.root / 'dns_service.py')],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
                dns_started = True
            self.sleep(.25)
        raise LaunchError('services_not_ready')

    def fresh_exit(self):
        try:
            return self.guard.verified_gate_for_launch()
        except Exception:
            raise LaunchError('exit_not_allowed') from None

    def internal_exit_probe(self):
        """Read-only exit check while held; cannot grant production permissions."""
        clock=getattr(self,'exit_probe_clock',time.monotonic)
        pause=getattr(self,'exit_probe_sleep',time.sleep)
        began=clock();deadline=began+HELD_EXIT_PREFLIGHT_BUDGET
        diagnostic={'schema':1,'operation':'native_held_fixed_exit_preflight',
                    'result':'pending','attempts':[],'permission_granted':False}
        self.exit_preflight_diagnostic=diagnostic
        for source in HELD_EXIT_PREFLIGHT_SOURCES:
            now=clock()
            if now<began:
                diagnostic['result']='clock_invalid';raise LaunchError('exit_not_allowed')
            remaining=deadline-now
            if remaining<=0:break
            try:
                actual,attempt=one_held_fixed_exit_attempt(self.guard,source,
                    min(HELD_EXIT_ATTEMPT_BUDGET,remaining),clock=clock)
            except HeldExitAttemptFailure as error:
                diagnostic['attempts'].append(error.diagnostic)
                if not error.diagnostic['retryable']:
                    diagnostic['result']='hard_failure';raise LaunchError('exit_not_allowed') from None
            except Exception:
                diagnostic['attempts'].append({'source':source,'stage':'internal',
                    'result':'failed','error_type':'internal_error','retryable':False})
                diagnostic['result']='hard_failure';raise LaunchError('exit_not_allowed') from None
            else:
                diagnostic['attempts'].append(attempt)
                if not 0<=clock()-began<HELD_EXIT_PREFLIGHT_BUDGET:
                    diagnostic['result']='unavailable';raise LaunchError('exit_verification_unavailable')
                diagnostic['result']='verified'
                return actual
            remaining=deadline-clock()
            if remaining<=.15:break
            pause(min(.15,remaining))
        diagnostic['result']='unavailable'
        raise LaunchError('exit_verification_unavailable')

    def launch(self):
        self._created_main = None
        self._created_process = None
        previous = os.environ.get('CLAUDE_DEV_TOOLS')
        original_popen = self.guard.subprocess.Popen

        def record_created_process(command, *args, **kwargs):
            is_claude = (isinstance(command, (list, tuple)) and command
                         and same_path(command[0], self.candidate))
            if is_claude:
                # Chromium 152 otherwise treats a fully occluded DevTools
                # frontend as hidden. Do not pass this main-process switch to
                # explicit child invocations; preserve the caller's argv.
                head=list(command[1:])
                if '--' in head:
                    head=head[:head.index('--')]
                if not any(isinstance(arg,str) and arg.partition('=')[0].casefold()=='--type' for arg in head):
                    command=monitor_launch_arguments(command)
                # Supply defaults only to this exact Claude invocation and the
                # children that inherit its environment. This is not a Windows
                # native timezone override or proof that every helper honors TZ.
                # Copy even an explicit env so neither the caller nor this
                # launcher's process-wide environment is mutated.
                launch_env = kwargs.get('env')
                launch_env = dict(os.environ if launch_env is None else launch_env)
                launch_env.update(TZ='America/New_York', LANG='en_US.UTF-8',
                                  LC_ALL='en_US.UTF-8')
                kwargs['env'] = launch_env
            process = original_popen(command, *args, **kwargs)
            # guard.launch also runs short PowerShell preflights. Only the
            # exact Claude executable created by this invocation is ours.
            if is_claude:
                self._created_process = process
                self._created_main = self.created_process_identity(process)
            return process

        os.environ['CLAUDE_DEV_TOOLS'] = 'undocked'
        self.guard.subprocess.Popen = record_created_process
        try:
            self.guard.launch()
        finally:
            self.guard.subprocess.Popen = original_popen
            if previous is None:
                os.environ.pop('CLAUDE_DEV_TOOLS', None)
            else:
                os.environ['CLAUDE_DEV_TOOLS'] = previous

    def created_process_identity(self, process):
        """Read creation identity from our Popen handle, not a reusable PID."""
        k = C.WinDLL('kernel32', use_last_error=True)
        k.GetProcessTimes.argtypes = [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4
        k.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
        handle = W.HANDLE(int(process._handle))
        creation, exited, kernel, user = [W.FILETIME() for _ in range(4)]
        image, size = C.create_unicode_buffer(32768), W.DWORD(32768)
        if (not k.GetProcessTimes(handle, C.byref(creation), C.byref(exited), C.byref(kernel), C.byref(user))
                or not k.QueryFullProcessImageNameW(handle, 0, image, C.byref(size))
                or not same_path(image.value, self.candidate)):
            raise LaunchError('ambiguous_main_process')
        stamp = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        return dict(pid=process.pid, creation=f'{stamp:016x}', image=canonical(image.value))

    def require_startup_hold(self, hold):
        """Retry incomplete startup observations only inside our offline lock."""
        if (not isinstance(hold, OwnedHold) or not hold.owned
                or not same_path(hold.root, self.root)
                or hold.owner.get('pid') != os.getpid()):
            raise LaunchError('foreign_hold')
        if self.alive(hold.owner) is not True:
            raise LaunchError('hold_owner_unknown')
        try:
            current, expected = hold.file.read(), hold.value()
            if any(current.get(key) != expected[key] for key in expected if key != 'created_at'):
                raise ValueError('hold changed')
        except Exception:
            raise LaunchError('foreign_hold') from None

    def startup_snapshot(self, rows):
        """Return complete rows for early rejection, never for admission alone.

        CIM can briefly report a just-created/exiting child without its path or
        command line. Such a row remains unresolved; it is not skipped when a
        complete snapshot is required for the final strict preflight.
        """
        if not isinstance(rows, list):
            return [], True
        complete, incomplete = [], False
        for row in rows:
            if (not isinstance(row, dict) or type(row.get('ProcessId')) is not int
                    or row['ProcessId'] <= 0 or not isinstance(row.get('ExecutablePath'), str)
                    or not row['ExecutablePath'].strip()):
                incomplete = True
                continue
            if same_path(row['ExecutablePath'], self.candidate):
                try:
                    argv = self.guard.windows_command_line_args(row.get('CommandLine'))
                    if not argv or not isinstance(row.get('CommandLine'), str) or not row['CommandLine'].strip():
                        raise ValueError('incomplete command line')
                except Exception:
                    incomplete = True
                    continue
            complete.append(row)
        return complete, incomplete

    def await_main(self, startup_hold=None):
        # Freeze the identity read from this Popen's native process handle.
        # A later PID/creation/image change is never a retryable CIM omission.
        captured = getattr(self, '_created_main', None)
        if (not isinstance(captured, dict) or type(captured.get('pid')) is not int
                or captured['pid'] <= 0 or not re.fullmatch(r'[0-9a-f]{16}', str(captured.get('creation', '')))
                or not isinstance(captured.get('image'), str)
                or not same_path(captured['image'], self.candidate)):
            raise LaunchError('ambiguous_main_process')
        expected = dict(captured)
        clock = getattr(self, 'startup_clock', time.monotonic)
        deadline = clock() + 18
        while clock() < deadline:
            self.require_startup_hold(startup_hold)
            if self.alive(expected) is not True:
                raise LaunchError('ambiguous_main_process')
            try:
                rows = self.guard.claude_process_snapshot()
            except Exception:
                rows = None
            if clock() >= deadline:
                break
            complete, incomplete = self.startup_snapshot(rows)
            # Reject fully observed bad flags, unknown child types and multiple
            # mains immediately, even alongside an unresolved unrelated row.
            result = self.find_main(rows=complete)
            if result and (result['pid'] != expected['pid']
                           or result['creation'] != expected['creation']
                           or not same_path(result['image'], expected['image'])):
                raise LaunchError('ambiguous_main_process')
            try:
                self.strict_launch_preflight(rows=complete)
            except Exception:
                raise LaunchError('unsafe_existing_process') from None
            if not incomplete and result:
                # Use the same coherent observation for the full strict check.
                # Nothing unresolved can gain permission from the early check.
                try:
                    self.strict_launch_preflight(rows=rows)
                except Exception:
                    raise LaunchError('unsafe_existing_process') from None
                self.require_startup_hold(startup_hold)
                if self.alive(expected) is not True:
                    raise LaunchError('ambiguous_main_process')
                if clock() >= deadline:
                    break
                return result
            self.sleep(.25)
        raise LaunchError('new_main_not_found')

    def wait_real_metadata(self, identity):
        deadline = self.now() + 30
        while self.now() < deadline:
            try:
                inspected = self.helper('inspect', identity)
                windows = ci_get(inspected, 'windows', [])
                ready = (isinstance(windows, list) and any(
                    ci_get(window, 'kind') == 'devtools-claude' for window in windows))
                if not ready:
                    self.sleep(.4)
                    continue
                # A reload can have changed the window title before its new
                # main-world Console context is ready. Do not paste a nonce
                # expression into the outgoing context during that handover.
                if self.now() + .3 >= deadline:
                    break
                self.sleep(.3)
                data = self.helper('verify', identity)
            except LaunchError as exc:
                if exc.code != 'helper_failed':
                    raise
                self.sleep(.4)
                continue
            origin = ci_get(data, 'origin')
            if isinstance(ci_get(data, 'metadata'), dict):
                origin = ci_get(ci_get(data, 'metadata'), 'origin')
            if origin == EXPECTED_ORIGIN:
                return metadata(data, real_origin=True, now=self.now())
            # Never tolerate an unexpected third-party origin during admission.
            if origin not in {'null', 'chrome-error://chromewebdata', 'chrome-error://chromewebdata/', 'about:blank'}:
                raise LaunchError('wrong_origin')
            self.sleep(.4)
        raise LaunchError('wrong_origin')

    def normal_exit_exact(self, identity):
        """Restart Manager request bound to PID + creation FILETIME, never force."""
        if self.alive(identity) is False:
            return True
        if self.alive(identity) is not True or not same_path(identity['image'], self.candidate):
            return False
        class Unique(C.Structure):
            _fields_ = [('pid', W.DWORD), ('start', W.FILETIME)]
        class Info(C.Structure):
            _fields_ = [('process', Unique), ('app', W.WCHAR * 256), ('service', W.WCHAR * 64),
                        ('type', C.c_int), ('status', W.ULONG), ('session', W.DWORD), ('restartable', W.BOOL)]
        rm = C.WinDLL('rstrtmgr', use_last_error=True)
        rm.RmStartSession.argtypes = [C.POINTER(W.DWORD), W.DWORD, W.LPWSTR]
        rm.RmRegisterResources.argtypes = [W.DWORD, W.UINT, C.c_void_p, W.UINT, C.POINTER(Unique), W.UINT, C.c_void_p]
        rm.RmGetList.argtypes = [W.DWORD, C.POINTER(W.UINT), C.POINTER(W.UINT), C.POINTER(Info), C.POINTER(W.DWORD)]
        rm.RmShutdown.argtypes = [W.DWORD, W.ULONG, C.c_void_p]
        rm.RmEndSession.argtypes = [W.DWORD]
        session, key = W.DWORD(), C.create_unicode_buffer(33)
        if rm.RmStartSession(C.byref(session), 0, key):
            return False
        try:
            stamp = int(identity['creation'], 16)
            unique = Unique(identity['pid'], W.FILETIME(stamp & 0xFFFFFFFF, stamp >> 32))
            if rm.RmRegisterResources(session, 0, None, 1, C.byref(unique), 0, None):
                return False
            needed, count, reboot, rows = W.UINT(), W.UINT(8), W.DWORD(), (Info * 8)()
            if (rm.RmGetList(session, C.byref(needed), C.byref(count), rows, C.byref(reboot))
                    or reboot.value or count.value != 1 or rows[0].process.pid != identity['pid']):
                return False
            if rm.RmShutdown(session, 0, None):
                return False
            deadline = self.now() + 5
            while self.now() < deadline:
                if self.alive(identity) is False:
                    return True
                self.sleep(.1)
            return False
        finally:
            rm.RmEndSession(session)

    def no_main(self):
        try:
            return self.find_main() is None
        except Exception:
            return False

    def native_rtc_module(self):
        """Only execute the exact manifest-bound controller bytes from this root."""
        leases = self.lease_json_io()
        source_path = physical_path(self.here / 'native_rtc_policy.py', boundary=self.root)
        manifest = small_json(self.here / 'native-rtc-manifest.json', boundary=self.root)
        if (type(manifest) is not dict or set(manifest) != {'schema','runtime_sha256','module_sha256'}
                or type(manifest.get('schema')) is not int or manifest['schema'] != 1
                or any(type(manifest.get(k)) is not str or not re.fullmatch('[0-9a-f]{64}',manifest[k])
                       for k in ('runtime_sha256','module_sha256'))):
            raise LaunchError('native_rtc_setup_failed')
        source = source_path.read_bytes()
        if len(source) > 131072 or hashlib.sha256(source).hexdigest() != manifest['module_sha256']:
            raise LaunchError('native_rtc_setup_failed')
        module = getattr(self, '_rtc_module', None)
        if module is None or getattr(module,'LOADED_MODULE_SHA256',None) != manifest['module_sha256']:
            spec = importlib.util.spec_from_file_location('claude_native_launch_rtc_' + manifest['module_sha256'], source_path)
            if spec is None or spec.loader is None:
                raise LaunchError('native_rtc_setup_failed')
            module = importlib.util.module_from_spec(spec)
            exec(compile(source, str(source_path), 'exec'), module.__dict__)
            self._rtc_module = module
        module.pins(self.root, leases)
        return module

    def verify_native_rtc(self, target):
        try:
            nonce = self._rtc_nonce
            if type(nonce) is not str or not re.fullmatch('[0-9a-f]{32}', nonce):
                raise ValueError('nonce')
            return self.native_rtc_module().verify(self.root,target,nonce,self.lease_json_io())
        except Exception:
            raise LaunchError('native_rtc_setup_failed') from None

    def native_inspector_listeners(self):
        rows = self.powershell(
            "$rows=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | "
            "Where-Object {$_.LocalPort -eq 9229} | "
            "Select-Object LocalAddress,LocalPort,OwningProcess); "
            "ConvertTo-Json -InputObject $rows -Compress", timeout=8)
        if (type(rows) is not list or len(rows) > 8
                or any(type(row) is not dict or set(row) != {'LocalAddress','LocalPort','OwningProcess'}
                       or type(row['LocalAddress']) is not str or type(row['LocalPort']) is not int
                       or row['LocalPort'] != 9229 or type(row['OwningProcess']) is not int
                       or row['OwningProcess'] <= 0 for row in rows)):
            raise LaunchError('native_rtc_setup_failed')
        return rows

    def require_native_inspector_owner(self, target):
        current = self.identity(target['pid'])
        if (not current or current['creation'] != target['creation']
                or not same_path(current['image'],target['image'])):
            raise LaunchError('native_rtc_setup_failed')
        rows = self.native_inspector_listeners()
        if (len(rows) != 1 or rows[0]['LocalAddress'] != '127.0.0.1'
                or rows[0]['OwningProcess'] != target['pid']):
            raise LaunchError('native_rtc_setup_failed')
        # PID reuse while the socket inventory was obtained cannot be accepted.
        after = self.identity(target['pid'])
        if (not after or after['creation'] != target['creation']
                or not same_path(after['image'], target['image'])):
            raise LaunchError('native_rtc_setup_failed')

    def close_owned_native_inspector(self, target, opened):
        """Never toggle an existing/foreign debugger; always prove final absence."""
        deadline = time.monotonic() + .75
        while True:
            rows = self.native_inspector_listeners()
            if not rows:
                return
            if time.monotonic() >= deadline:
                break
            self.sleep(.05)
        if not opened:
            raise LaunchError('native_rtc_inspector_cleanup_failed')
        try:
            self.require_native_inspector_owner(target)
            native_inspector_ack('main-inspector-close',self.helper('main-inspector-close',target))
            deadline = time.monotonic() + 2
            while self.native_inspector_listeners():
                if time.monotonic() >= deadline:
                    raise ValueError('inspector_still_open')
                self.sleep(.05)
        except Exception:
            raise LaunchError('native_rtc_inspector_cleanup_failed') from None

    def prepare_native_rtc(self, target, hold):
        """Install native RTC policy while the caller owns the offline hold."""
        if not hold.owned:
            raise LaunchError('native_rtc_setup_failed')
        opened = enable_attempted = False
        try:
            module = self.native_rtc_module()  # Pin before enabling a debugger.
            if self.native_inspector_listeners():
                raise LaunchError('native_rtc_setup_failed')
            # A helper may invoke the menu and fail before its acknowledgement.
            # Only after proving no pre-existing listener may cleanup close an
            # exact target-owned listener created during this attempt.
            enable_attempted = True
            data = native_inspector_ack('main-inspector',self.helper('main-inspector',target))
            if ci_get(data,'stateBefore') != 'off' or ci_get(data,'invoked') is not True:
                raise LaunchError('native_rtc_setup_failed')
            opened = True
            self.require_native_inspector_owner(target)
            module.install(self.root,target,self._rtc_nonce,self.lease_json_io(),
                           self.require_native_inspector_owner,
                           lambda: self.close_owned_native_inspector(target,opened))
        except LaunchError:
            raise
        except Exception:
            raise LaunchError('native_rtc_setup_failed') from None
        finally:
            # Covers helper/owner failures before core.install starts as well.
            self.close_owned_native_inspector(target,opened or enable_attempted)
        self.verify_native_rtc(target)
        # Official main debugging can change the active DevTools target. Restore
        # and verify the original renderer's Sensors/Console setup before release.
        self.helper('configure',target)
        metadata(self.helper('verify',target),real_origin=False,now=self.now())
        self.verify_native_rtc(target)

    def require_existing_native_rtc(self, target):
        try:
            _, monitor = self.environment_modules()
            active = monitor.active_monitor('native',target,root=self.root)
            if not active or type(active.get('nonce')) is not str:
                raise ValueError('no_verified_monitor')
            self._rtc_nonce = active['nonce']
            self.verify_native_rtc(target)
            return active
        except Exception:
            raise LaunchError('native_rtc_restart_required') from None

    def environment_modules(self):
        for name in ('environment_lease.py','environment_watchdog.py'):
            physical_path(self.root / name,boundary=self.root)
        if str(self.root) not in sys.path:
            sys.path.insert(0,str(self.root))
        import environment_lease as leases
        import environment_watchdog as monitor
        if (not same_path(leases.__file__,self.root / 'environment_lease.py')
                or not same_path(monitor.__file__,self.root / 'environment_watchdog.py')):
            raise LaunchError('invalid_path')
        return leases, monitor

    def activate_environment_monitor(self, target, hold):
        # Import only the physical, private installation module. The monitor
        # does no input and cannot turn a stale status file into permission.
        leases, monitor = self.environment_modules()
        self.verify_native_rtc(target)
        existing = monitor.active_monitor('native', target, root=self.root)
        if existing:
            if existing.get('nonce') != self._rtc_nonce:
                raise LaunchError('native_rtc_restart_required')
            return existing
        previous = None
        locator = self.here / 'live-pin.json'
        try:
            saved = small_json(locator, boundary=self.root)
            if saved.get('schema') == 1 and re.fullmatch('[0-9a-f]{32}', saved.get('nonce', '')):
                previous = saved['nonce']
        except Exception:
            pass
        nonce = self._rtc_nonce
        checked = metadata(self.helper('arm-live', target, monitor_nonce=nonce, previous_nonce=previous),
                           real_origin=True, now=self.now())
        if checked['nonce'] != nonce:
            raise LaunchError('helper_failed')
        # This is only a locator for our own fixed expression, never authority
        # to renew a lease. It survives PID changes and prevents duplicate pins.
        self.save_live_locator(nonce)
        try:
            return monitor.start_monitor('native', target, nonce=nonce, root=self.root)
        except Exception:
            raise LaunchError('environment_monitor_not_ready') from None

    def lease_json_io(self):
        """Load the private, physically validated writer without ambient imports."""
        cached = getattr(self, '_lease_json_io', None)
        if cached is not None:
            return cached
        source = physical_path(self.root / 'environment_lease.py', boundary=self.root)
        spec = importlib.util.spec_from_file_location('claude_native_launch_lease_json_io', source)
        if spec is None or spec.loader is None:
            raise LaunchError('invalid_path')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self._lease_json_io = module
        return module

    def save_live_locator(self, nonce):
        if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
            raise LaunchError('helper_failed')
        locator = physical_path(self.here / 'live-pin.json', boundary=self.root, allow_missing=True)
        # The shared writer uses Windows FileRenameInfoEx POSIX semantics;
        # os.replace can fail against hot readers even with DELETE sharing.
        # Failure propagates and retains the previous complete locator.
        self.lease_json_io().atomic_json(locator, {'schema': 1, 'nonce': nonce})

    def publish(self, state):
        target = physical_path(self.here / 'native-current.json', boundary=self.here, allow_missing=True)
        report=dict(state,at_unix=self.now())
        if getattr(self,'helper_foreground_grants',None):
            report['helper_foreground_grants']=list(self.helper_foreground_grants)
        if getattr(self,'exit_preflight_diagnostic',None):
            report['exit_preflight_diagnostic']=dict(self.exit_preflight_diagnostic)
        self.lease_json_io().atomic_json(target,report)

    def diagnose(self):
        main = self.preflight()
        roles = self.check_services(self.service_snapshot())
        return dict(ok=True, mode='diagnose', read_only=True, package=self.package,
                    main_pid=main['pid'] if main else None,
                    hold_present=(self.root / 'hold.block').exists(),
                    services={k: v['ProcessId'] if v else None for k, v in roles.items()},
                    helper_sha256=self._helper_hash,
                    timezone_activation='not inspected in diagnose',
                    wfp_live_filters='not re-enumerated; installed marker is not new proof',
                    persistent_environment_lease=False)


def apply(backend, progress=None):
    """Transaction uses an injectable backend; offline tests never operate apps."""
    state = dict(ok=False, mode='starting', stage='preflight', persistent_environment_lease=False,
                 all_renderer_zero_window_proven=False, startup_before_controller_unverified=True)

    def set_stage(value):
        state['stage'] = value
        if progress is not None:
            try:
                progress(value)
            except Exception:
                pass  # Presentation failure cannot weaken the transaction.

    hold = target = None
    created = js_disabled = target_touched = released = launch_attempted = False
    set_stage('preflight')
    with backend.mutex() as instance:
        if not instance.acquired:
            return dict(ok=True, mode='already-running', code='another_launcher_running')
        try:
            target = backend.preflight()
            created = target is None
            state['mode'] = 'new-session' if created else 'existing-session'
            hold = backend.hold()
            hold.recover_existing()
            set_stage('services')
            state['services'] = backend.ensure_services()
            set_stage('exit-preflight')
            state['exit_ip'] = backend.internal_exit_probe() if hold.owned else backend.fresh_exit()
            if target is not None:
                state['main_pid'] = target['pid']
                # An old process without a matching native policy proof cannot
                # be repaired in place while preserving arbitrary live RTCs.
                # Require a normal cold restart; retain profiles and drafts.
                target_touched = True
                set_stage('existing-native-rtc-check')
                backend.require_existing_native_rtc(target)
                set_stage('existing-environment-check')
                try:
                    target_touched = True
                    checked = metadata(backend.helper('verify', target), real_origin=True, now=backend.now())
                except LaunchError:
                    checked = None
                if checked is not None:
                    # No reload, JS toggle, shutdown, or draft changes on reuse.
                    set_stage('continuous-environment-protection')
                    state['environment_monitor'] = backend.activate_environment_monitor(target, hold)
                    if hold.owned:
                        state['exit_ip'] = backend.internal_exit_probe()
                        hold.release()
                        released = True
                    backend.helper('park-monitor-bottom', target)
                    state.update(ok=True, mode='reused-existing-session', stage='ready', environment=checked,
                                 devtools_kept_attached=True, startup_before_controller_unverified=True,
                                 persistent_environment_lease=True)
                    backend.publish(state)
                    return state
                set_stage('reconfigure-existing')
                hold.acquire()
                backend.helper('configure', target)
                checked = metadata(backend.helper('verify', target), real_origin=False, now=backend.now())
                if checked['origin'] != EXPECTED_ORIGIN:
                    raise LaunchError('existing_error_page')
                set_stage('continuous-environment-protection')
                state['environment_monitor'] = backend.activate_environment_monitor(target, hold)
                state['exit_ip'] = backend.internal_exit_probe()
                hold.release()
                released = True
                backend.helper('park-monitor-bottom', target)
                state.update(ok=True, mode='reconfigured-existing-session', stage='ready', environment=checked,
                             devtools_kept_attached=True, startup_before_controller_unverified=True,
                             existing_session_reloaded=False, persistent_environment_lease=True)
                backend.publish(state)
                return state

            set_stage('offline-start')
            hold.acquire()
            launch_attempted = True
            state['launch_attempted'] = True
            backend.launch()
            target = backend.await_main(startup_hold=hold)
            target_touched = True
            state['main_pid'] = target['pid']
            set_stage('disable-js')
            # A helper error can be ambiguous after sending a command. Rollback
            # attempts enable-js even if disable-js failed before its reply.
            js_disabled = True
            backend.helper('disable-js', target)
            set_stage('offline-configure')
            backend.helper('configure', target)
            metadata(backend.helper('verify', target), real_origin=False, now=backend.now())
            set_stage('offline-native-rtc')
            backend.prepare_native_rtc(target, hold)
            state['native_webrtc_policy'] = 'disable_non_proxied_udp'
            state['native_webrtc_policy_verified_before_network_release'] = True
            set_stage('held-exit-probe')
            state['exit_ip'] = backend.internal_exit_probe()
            set_stage('release-for-html-only')
            hold.release()
            released = True
            set_stage('real-page-js-disabled')
            backend.helper('reload', target)
            backend.wait_real_metadata(target)
            set_stage('enable-js')
            backend.helper('enable-js', target)
            js_disabled = False
            backend.helper('reload', target)
            set_stage('final-real-page-check')
            checked = backend.wait_real_metadata(target)
            set_stage('continuous-environment-protection')
            state['environment_monitor'] = backend.activate_environment_monitor(target, hold)
            if hold.owned:
                state['exit_ip'] = backend.internal_exit_probe()
                hold.release()
            backend.helper('park-monitor-bottom', target)
            state.update(ok=True, stage='ready', environment=checked, devtools_kept_attached=True,
                         startup_network_held_until_initial_environment_check=True,
                         startup_before_controller_unverified=False, persistent_environment_lease=True)
            backend.publish(state)
            return state
        except Exception as exc:
            state.update(ok=False, code=safe_error(exc), failed_stage=state['stage'], stage='failed')
            if getattr(backend,'exit_preflight_diagnostic',None):
                state['exit_preflight_diagnostic']=dict(backend.exit_preflight_diagnostic)
            # Fail closed before restoring JS or attempting normal shutdown.
            blocked = False
            if hold is not None and (hold.owned or released or target_touched):
                try:
                    hold.acquire()
                    blocked = hold.owned
                except Exception:
                    state['hold_reacquire_failed_or_foreign_hold_preserved'] = True
                    state['block_unknown'] = True
            if js_disabled and target is not None and blocked:
                try:
                    backend.helper('enable-js', target)
                    state['rollback_js_restored'] = True
                except Exception:
                    state['rollback_js_restored'] = False
            elif js_disabled:
                state['block_unknown'] = True
                state['rollback_js_restored'] = False
            exited = False
            if created and target is not None:
                try:
                    exited = backend.normal_exit_exact(target) is True
                except Exception:
                    pass
                state['new_session_exited_normally'] = exited
            elif (created and not launch_attempted and not target_touched
                  and not getattr(hold, 'recovered', False)):
                exited = backend.no_main() is True
                state['no_launch_attempted_and_no_main_confirmed'] = exited
            elif created and launch_attempted:
                # A slow or delegated launch may appear after a no-main
                # snapshot. Keep the hold until an exact identity is known.
                state['unconfirmed_launch_identity_hold_retained'] = True
            if blocked:
                if created and exited:
                    try:
                        hold.release()
                        state['own_hold_removed_after_confirmed_exit'] = True
                    except Exception:
                        state['own_hold_removed_after_confirmed_exit'] = False
                else:
                    state['offline_hold_retained'] = True
                    if created:
                        state['rollback_code'] = 'rollback_exit_not_confirmed'
            try:
                if getattr(backend, 'helper_failures', None):
                    state['helper_failures'] = list(backend.helper_failures)
                backend.publish(state)
            except Exception:
                pass
            return state
        finally:
            if hold is not None:
                hold.close_preserving()


STAGE_TEXT = {
    'preflight': '正在检查 Claude 和启动组件…',
    'services': '正在检查联网保护和定向 DNS…',
    'exit-preflight': '正在验证指定的住宅出口…',
    'existing-environment-check': '正在检查当前 Claude 环境…',
    'existing-native-rtc-check': '正在检查当前会话的原生 WebRTC 保护…',
    'reconfigure-existing': '正在调整当前会话的时区和语言…',
    'offline-start': '正在离线准备 Claude…',
    'disable-js': '正在准备安全的页面加载…',
    'offline-configure': '正在配置美东时区和英语…',
    'offline-native-rtc': '正在配置原生 WebRTC 隐私保护…',
    'held-exit-probe': '正在复核住宅出口…',
    'release-for-html-only': '正在准备受保护的联网加载…',
    'real-page-js-disabled': '正在验证实际 Claude 页面…',
    'enable-js': '正在完成页面初始化…',
    'final-real-page-check': '正在进行最后的环境检查…',
    'continuous-environment-protection': '正在启用后台环境失效断网保护…',
}


def write_startup_progress(value):
    """Best-effort diagnostics only; no reader may treat this as permission."""
    import tempfile
    target=physical_path(HERE/'startup-progress.json',boundary=ROOT,allow_missing=True)
    temporary=None
    try:
        fd,name=tempfile.mkstemp(prefix='startup-progress-',suffix='.tmp',dir=HERE)
        temporary=Path(name)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(value,stream,separators=(',',':'));stream.flush()
        os.replace(temporary,target)
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()


class GuiProgressTelemetry:
    """One bounded metadata snapshot; failures cannot authorize or stop work."""
    def __init__(self,writer=write_startup_progress,*,clock=time.time,pid=None):
        self.writer,self.clock=writer,clock
        self.pid=os.getpid() if pid is None else pid
        self.stage='initialization';self.pending=False;self.command=None
        self.lock=threading.Lock()

    def update(self,*,stage=None,pending=None,command=None):
        try:
            with self.lock:
                if stage is not None:
                    self.stage=stage if stage in STAGE_TEXT or stage in ('initialization','ready','failed') else 'unrecognized'
                if pending is not None:
                    self.pending=pending is True
                    self.command=command if self.pending and command in HELPER_FOREGROUND_COMMANDS else None
                value={'schema':1,'diagnostic_only':True,'pid':self.pid,'stage':self.stage,
                       'gui_pending':self.pending,'helper_command':self.command,'updated_at':self.clock()}
                # Serialize writers across the GUI/preparation threads so an
                # older queued observation cannot overwrite a newer snapshot.
                self.writer(value)
        except Exception:
            pass


class GuiCoordinator:
    """UI-thread dispatcher; all blocking work runs in one separate worker."""
    def __init__(self, backend_factory, schedule, start_worker, on_stage, on_done):
        self.backend_factory, self.schedule = backend_factory, schedule
        self.start_worker, self.on_stage, self.on_done = start_worker, on_stage, on_done
        self.events, self.result, self.done = queue.SimpleQueue(), None, False

    def start(self):
        # Let the normal, user-launched GUI be mapped before background work.
        self.schedule(120, self._start)

    def _start(self):
        self.start_worker(self._work)
        self.schedule(75, self.poll)

    def _work(self):
        try:
            result = apply(self.backend_factory(), progress=lambda stage: self.events.put(('stage', stage)))
        except Exception as exc:
            result = dict(ok=False, code=safe_error(exc), stage='initialization')
        self.events.put(('done', result))

    def poll(self):
        if self.done:
            return
        while True:
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'stage':
                self.on_stage(value)
            else:
                self.result, self.done = value, True
                self.on_done(value)
                return
        self.schedule(75, self.poll)


def error_message(result):
    message = MESSAGES.get(result.get('code'), MESSAGES['unexpected_failure'])
    if result.get('offline_hold_retained'):
        message += '\n\n本次离线锁已保留，没有自动退出或清理你的已有工作。'
    if result.get('block_unknown'):
        message += '\n\n无法确认本次维护锁的状态。请保存工作并完整退出 Claude 后重试。'
    return message


def gui_apply(backend_factory, *, gui_mutex_factory=None, window_runner=None):
    # Acquire before importing/mapping Tk. A second GUI must not steal focus
    # from the first launcher's foreground-checked helper transaction.
    factory = gui_mutex_factory or (lambda: SingleInstance(ROOT, scope='gui'))
    with factory() as instance:
        if not instance.acquired:
            return dict(ok=True, mode='already-running', code='another_launcher_running')
        return (window_runner or _gui_apply_window)(backend_factory)


def _gui_apply_window(backend_factory):
    import tkinter as tk
    from tkinter import messagebox, ttk

    window = tk.Tk()
    window.title('Claude 一键安全环境')
    window.geometry('420x230')
    window.resizable(False, False)
    telemetry=GuiProgressTelemetry()
    telemetry.update(stage='initialization',pending=False)
    backend_holder=[]
    # No topmost flag, repeated focus forcing, or foreground-all permission.
    text = tk.StringVar(value='正在准备 Claude 安全环境…')
    frame = ttk.Frame(window, padding=20)
    frame.pack(fill='both', expand=True)
    ttk.Label(frame, textvariable=text, wraplength=380).pack(anchor='w', pady=(0, 14))
    bar = ttk.Progressbar(frame, mode='indeterminate', length=375)
    bar.pack(fill='x')
    button=ttk.Button(frame,text='继续配置')
    ttk.Label(frame, text='准备期间关闭此窗口会将它最小化。', wraplength=380).pack(anchor='w', pady=(12, 0))
    window.protocol('WM_DELETE_WINDOW', window.iconify)
    bar.start(12)

    # Resolve only this physical sibling module, not a module from cwd/PATH.
    bridge_path=physical_path(HERE/'foreground_gui.py',boundary=ROOT)
    bridge_spec=importlib.util.spec_from_file_location('claude_native_foreground_gui',bridge_path)
    bridge_module=importlib.util.module_from_spec(bridge_spec)
    bridge_spec.loader.exec_module(bridge_module)

    def show_continue():
        # Show this app's own pending-button window once per new request.
        # No focus_force/topmost, cross-window input or automatic Continue.
        window.deiconify()
        window.lift()
        bar.stop()
        text.set('Windows 需要一次窗口操作授权。请点击【继续配置】；网络限制和登录资料保持不变。')
        button.pack(anchor='w',pady=(12,0))

    def hide_continue():
        button.pack_forget()
        text.set('正在继续准备 Claude 安全环境…')
        bar.start(12)

    bridge=bridge_module.UserForegroundRetry(show_continue,hide_continue)
    button.configure(command=bridge.continue_pending)  # Only a real button click.

    def request_foreground_retry(attempt):
        backend=backend_holder[0] if backend_holder else None
        command=getattr(backend,'_pending_foreground_command',None)
        telemetry.update(pending=True,command=command)
        try:
            return bridge.request(attempt)
        except bridge_module.ForegroundRetryUnavailable:
            raise LaunchError('helper_continue_cancelled') from None
        finally:
            telemetry.update(pending=False)

    def interactive_backend():
        backend=backend_factory()
        backend_holder[:]=[backend]
        backend.foreground_retry=request_foreground_retry
        return backend

    def finished(result):
        telemetry.update(stage='ready' if result.get('ok') else 'failed',pending=False)
        bridge.close()
        bar.stop()
        if not result.get('ok'):
            window.deiconify()
            messagebox.showerror('Claude 一键安全环境', error_message(result), parent=window)
            result['gui_error_shown'] = True
        window.after(80, window.destroy)

    def show_stage(stage):
        text.set(STAGE_TEXT.get(stage, '正在准备 Claude 安全环境…'))
        telemetry.update(stage=stage)

    coordinator = GuiCoordinator(
        interactive_backend, window.after,
        lambda target: threading.Thread(target=target, name='ClaudeEnvironmentPrepare', daemon=False).start(),
        show_stage,
        finished,
    )
    def poll_foreground():
        if not coordinator.done:
            bridge.poll()
            window.after(75,poll_foreground)
    window.after(75,poll_foreground)
    coordinator.start()
    window.mainloop()
    return coordinator.result or dict(ok=False, code='unexpected_failure', stage='gui')


def main(argv=None, *, backend_factory=WindowsBackend):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--apply', action='store_true')
    group.add_argument('--diagnose', action='store_true')
    parser.add_argument('--gui', action='store_true')
    args = parser.parse_args(argv)
    if not args.apply and not args.gui:
        args.diagnose = True
    try:
        if args.gui and not args.diagnose:
            result = gui_apply(backend_factory)
        else:
            backend = backend_factory()
            result = backend.diagnose() if args.diagnose else apply(backend)
    except Exception as exc:
        result = dict(ok=False, code=safe_error(exc), stage='initialization')
    if not args.gui or args.diagnose:
        print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))
    elif not result.get('ok'):
        # Normally gui_apply already displayed its own error dialog. This
        # fallback is only for a failure while constructing the GUI itself.
        if result.get('stage') == 'initialization' and not result.get('gui_error_shown'):
            C.windll.user32.MessageBoxW(None, error_message(result), 'Claude 一键安全环境', 0x10)
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())
