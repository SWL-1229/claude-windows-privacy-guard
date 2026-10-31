"""Launch the private-pipe Claude environment behind an owned network hold.

This module does not change Windows locale, firewall rules, authentication data,
or the permitted exit set. It never opens a control server or kills processes.
"""
from __future__ import annotations

import ctypes
import datetime as dt
import http.client
import ipaddress
import json
import os
import re
import stat
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import environment_lease as _leases
import environment_watchdog as _watchdog
from browser_system_timezone import NATIVE_BROWSER_MODE, native_browser_arguments
from launch_failure_diagnostic import probe_blocker, snapshot as failure_snapshot, write_snapshot as write_failure_snapshot

from deployment_allowlist import ALLOWED as ALLOWED_EXITS
DOMAINS = ('claude.ai', 'claude.com', 'anthropic.com', 'claude.app',
           'claudeusercontent.com', 'claudemcpcontent.com')
SAFE_WARNINGS = frozenset({'early_unpaused_target', 'unknown_target_type_unverified',
                           'unpaused_navigation_scope_change'})


class LaunchFailure(RuntimeError):
    def __init__(self, code, *, hold_retained=False):
        super().__init__(code)
        self.code = code
        self.hold_retained = hold_retained


def _physical(path, *, directory=False):
    raw = Path(path)
    if not raw.is_absolute() or raw.resolve(strict=True) != raw.absolute():
        raise LaunchFailure('redirected_or_relative_runtime_path')
    if directory and not raw.is_dir():
        raise LaunchFailure('runtime_directory_missing')
    if not directory and not raw.is_file():
        raise LaunchFailure('runtime_file_missing')
    return raw.resolve(strict=True)


def _allowlist(root):
    try:
        policy = _physical(root / 'policy.json')
        obj = json.loads(policy.read_text(encoding='utf-8-sig'))
        if not isinstance(obj, dict) or not isinstance(obj.get('allowed_exit_ips'), list):
            raise ValueError()
        values = frozenset(str(ipaddress.ip_address(item)) for item in obj['allowed_exit_ips'])
        if not values or not values.issubset(ALLOWED_EXITS):
            raise ValueError()
        return values
    except (OSError, ValueError, TypeError):
        raise LaunchFailure('invalid_exit_allowlist') from None


PROBE_BUDGET = 16.0
SOCKET_TIMEOUT = 7.0
RETRY_DELAY = 0.25
TRANSIENT_STATUS = frozenset({429, 500, 502, 503, 504})


class _TransientProbeFailure(Exception):
    pass


def _budget_timeout(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LaunchFailure('exit_verification_unavailable')
    return min(SOCKET_TIMEOUT, remaining)


def _phase_timeout(connection, deadline):
    timeout = _budget_timeout(deadline)
    connection.timeout = timeout
    if connection.sock is not None:
        connection.sock.settimeout(timeout)


def _one_probe(root, port, deadline):
    # Read current policy for every attempt; no stale policy survives a retry.
    allowed = _allowlist(root)
    connection = http.client.HTTPSConnection(
        '127.0.0.1', port, timeout=_budget_timeout(deadline))
    connection.set_tunnel('www.cloudflare.com', 443)
    response = None
    try:
        # Default HTTPSConnection context verifies the destination certificate.
        # The fixed CONNECT route ignores proxy environment and system bypasses.
        connection.connect()
        _phase_timeout(connection, deadline)
        connection.request('GET', '/cdn-cgi/trace')
        _phase_timeout(connection, deadline)
        response = connection.getresponse()
        _phase_timeout(connection, deadline)
        if response.status in TRANSIENT_STATUS:
            raise _TransientProbeFailure()
        if response.status != 200:
            raise LaunchFailure('exit_verification_unavailable')
        body = response.read(8192)
        _budget_timeout(deadline)
        fields = dict(line.split('=', 1) for line in body.decode('ascii').splitlines()
                      if '=' in line)
        actual = str(ipaddress.ip_address(fields['ip']))
        if actual not in allowed or actual not in _allowlist(root):
            raise LaunchFailure('exit_outside_allowlist')
        # Policy I/O or parsing must not make a late result admissible either.
        _budget_timeout(deadline)
        return actual
    finally:
        if response is not None:
            response.close()
        connection.close()


def _verified_exit(root, port):
    if type(port) is not int or port not in (17894, 17895):
        raise LaunchFailure('unauthorized_proxy_port')
    _allowlist(root)  # Invalid policy is fatal before opening any socket.
    deadline = time.monotonic() + PROBE_BUDGET
    # 17894 already has a caller-owned 15-second retry loop. Do not multiply it.
    attempts = 2 if port == 17895 else 1
    for attempt in range(attempts):
        try:
            return _one_probe(root, port, deadline)
        except LaunchFailure:
            raise
        except ssl.SSLError:
            # Includes certificate/hostname errors; never retry TLS failures.
            raise LaunchFailure('exit_verification_unavailable') from None
        except (_TransientProbeFailure, TimeoutError, ConnectionError,
                http.client.RemoteDisconnected, http.client.IncompleteRead):
            if attempt + 1 >= attempts:
                raise LaunchFailure('exit_verification_unavailable') from None
            if deadline - time.monotonic() <= RETRY_DELAY:
                raise LaunchFailure('exit_verification_unavailable') from None
            time.sleep(RETRY_DELAY)
        except Exception:
            # Malformed body/status/protocol data does not broaden retries.
            raise LaunchFailure('exit_verification_unavailable') from None
    raise LaunchFailure('exit_verification_unavailable')

def probe_gateway_blocker(root):
    # Fresh diagnostic observation, never an admission grant. Do not remove
    # registrations or ignore a live process merely because its UI is hidden.
    try:
        return probe_blocker(_leases.LeaseRegistry(root))
    except Exception:
        return {'reason':'environment_registry_unavailable','kind':None,'target_pid':None}


def _capture_failure(root, stage, code, *, report=None, controller_pid=None, blocker=None):
    try:
        return failure_snapshot(stage, code, report=report, controller_pid=controller_pid,
                                blocker=probe_gateway_blocker(root) if blocker is None else blocker,
                                hold_retained=(Path(root)/'hold.block').exists())
    except Exception:
        return None


def _publish_failure(root, error, value):
    # The record never participates in permission checks. Failure to record is
    # best effort and cannot change the original error, rollback or routing.
    written=False
    try:
        if value is not None:
            written=write_failure_snapshot(root,value,_leases)
        error.launch_diagnostic_recorded=written
        error.launch_diagnostic_snapshot=value
    except Exception:
        pass
    return written


def record_launch_failure(root, error, *, stage='preflight', report=None,
                          controller_pid=None, blocker=None):
    if getattr(error,'launch_diagnostic_recorded',False) is True:
        return True
    value=getattr(error,'launch_diagnostic_snapshot',None)
    if value is None:
        value=_capture_failure(root,stage,getattr(error,'code','environment_launch_failed'),
                               report=report,controller_pid=controller_pid,blocker=blocker)
    return _publish_failure(root,error,value)


def _pid_alive(pid):
    """No process enumeration or broad termination; inspect only our child PID."""
    if type(pid) is not int or pid <= 0 or os.name != 'nt':
        return None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return False if ctypes.get_last_error() == 87 else None
    try:
        code = ctypes.c_ulong()
        return code.value == 259 if kernel.GetExitCodeProcess(handle, ctypes.byref(code)) else None
    finally:
        kernel.CloseHandle(handle)


def _read_status(status_path, started, kind):
    try:
        if status_path.resolve(strict=True) != status_path.absolute() or status_path.stat().st_size > 32768:
            return None
        # Node replaces this file atomically; Windows readers must share delete
        # access so an observation cannot deny the next status publication.
        boundary = status_path.parent.parent.parent
        if status_path.parent.name != 'runs' or status_path.parent.parent.name != 'privacy-qa':
            return None
        result = _leases.read_json(status_path, boundary)
        timestamp = dt.datetime.fromisoformat(result['at'].replace('Z', '+00:00'))
        if timestamp.tzinfo is None:
            return None
        stamp = timestamp.timestamp()
        if (result.get('schema_version') != 1 or result.get('kind') != kind or
                stamp < started - 1 or stamp > time.time() + 5 or
                status_path.stat().st_mtime < started - 1):
            return None
        return result
    except (OSError, KeyError, ValueError, TypeError, _leases.LeaseError):
        return None


def _environment_checked(report, now=None):
    if (not isinstance(report, dict) or report.get('environment_check_ok') is not True
            or report.get('environment_check_pending') is True):
        return False
    try:
        checked = dt.datetime.fromisoformat(report['environment_check_at'].replace('Z', '+00:00'))
        age = (time.time() if now is None else now) - checked.timestamp()
        return checked.tzinfo is not None and checked.utcoffset() == dt.timedelta(0) and 0 <= age <= 4
    except (KeyError, ValueError, TypeError, OverflowError):
        return False


def _real_failure(report):
    if not isinstance(report, dict):
        return False
    if report.get('status') in ('environment_failed', 'stopping', 'stopped', 'child_exited', 'child_shutdown_not_confirmed'):
        return True
    counts = report.get('counts', {})
    if not isinstance(counts, dict):
        return True
    for key in ('metadata_mismatches', 'command_errors', 'workers_unverified', 'environment_check_failures'):
        value = counts.get(key, 0)
        if type(value) is not int or value != 0:
            return True
    errors = report.get('error_codes', [])
    if not isinstance(errors, list):
        return True
    allowed = set(SAFE_WARNINGS)
    # Chromium may not expose emulation commands on workers. That diagnostic
    # is not itself a mismatched environment; the fresh all-target sweep below
    # must still prove the inherited metadata before readiness can succeed.
    allowed.add('worker_override_unavailable')
    return any(code not in allowed for code in errors)


def _ready(report):
    if not isinstance(report, dict):
        return False
    if report.get('environment_scope') != 'isolated-browser-all-web-targets-v1' or _real_failure(report):
        return False
    counts = report.get('counts', {})
    if not isinstance(counts, dict) or type(report.get('process_pid')) is not int:
        return False
    if not (type(counts.get('metadata_matches')) is int and counts['metadata_matches'] >= 1):
        return False
    if not (type(counts.get('environment_checks')) is int and counts['environment_checks'] >= 1):
        return False
    if not _environment_checked(report):
        return False
    if any(counts.get(key) != 0 for key in ('metadata_mismatches', 'command_errors', 'workers_unverified')):
        return False
    errors = report.get('error_codes', [])
    if not isinstance(errors, list):
        return False
    allowed = set(SAFE_WARNINGS)
    if counts.get('workers_inherited_verified', 0) > 0 or _environment_checked(report):
        allowed.add('worker_override_unavailable')
    return (report.get('status') not in ('stopping', 'stopped', 'child_exited', 'child_shutdown_not_confirmed')
            and all(code in allowed for code in errors))


def _native_ready(report, *, initial=False):
    """Policy readiness is independent of whether the remote document loaded.

    The startup JS/ICE result retains its original timestamp. Only the owning
    native monitor can grant fresh OS/actual-arguments policy observations.
    """
    try:
        if (type(report) is not dict or _real_failure(report)
                or report.get('verification_mode') != NATIVE_BROWSER_MODE
                or report.get('profile_scope') != 'claude-persistent'):
            return False
        target = _leases.identity(report['process_pid'])
        if not target:
            return False
        startup = report['startup_runtime']
        checked = dt.datetime.fromisoformat(startup['checked_at'].replace('Z', '+00:00')).timestamp()
        now = time.time()
        record = {'kind': 'browser', 'verification_mode': NATIVE_BROWSER_MODE,
                  'target': target, 'bootstrap_checked_at': checked,
                  'startup_runtime_sha256': _leases.native_startup_fingerprint(startup)}
        _leases.native_browser_source(report, record, now)
        return not initial or 0 <= now - checked < 4
    except (KeyError, TypeError, ValueError, OSError, _leases.LeaseError):
        return False


def verify_native_browser_monitor(root, target, controller, status_path, *, monitor=None):
    """Reuse one exact registered instance; never recreate or renew its nonce."""
    try:
        current = _watchdog.active_monitor('browser', target, root=root,
                                           verification_mode=NATIVE_BROWSER_MODE)
        expected = Path(root) / 'privacy-qa' / 'runs' / f"environment-browser-{controller['pid']}.json"
        if current is None or Path(status_path) != expected:
            raise _leases.LeaseError('native_browser_monitor_not_current')
        if monitor is not None and any(current.get(k) != monitor.get(k)
                                        for k in ('nonce', 'registration', 'monitor_pid')):
            raise _leases.LeaseError('native_browser_monitor_changed')
        registration = Path(root) / 'environment-leases' / (_leases.key_for('browser', target) + '.registration.json')
        if Path(current['registration']) != registration:
            raise _leases.LeaseError('native_browser_registration_invalid')
        record = _leases.read_json(registration, root)
        if (record.get('verification_mode') != NATIVE_BROWSER_MODE or record.get('nonce') != current['nonce']
                or not _leases.same_identity(record.get('target'), target)
                or not _leases.same_identity(record.get('controller'), controller)
                or record.get('source') != str(expected)
                or record.get('monitor', {}).get('pid') != current['monitor_pid']):
            raise _leases.LeaseError('native_browser_registration_invalid')
        observation = _watchdog.native_browser_policy_observation(root, target, controller,
                                                                  str(expected), record=record)
        after = _watchdog.active_monitor('browser', target, root=root,
                                         verification_mode=NATIVE_BROWSER_MODE)
        if (after is None or any(after.get(k) != current.get(k)
                                for k in ('nonce', 'registration', 'monitor_pid'))
                or observation.get('reason') != 'native_browser_policy_verified'
                or not 0 <= time.time() - observation['checked_at'] < 4):
            raise _leases.LeaseError('native_browser_monitor_changed')
        return current, observation
    except _leases.LeaseError as error:
        raise LaunchFailure(str(error)) from None


def _start_browser_monitor(root, controller_pid, report, status_path, *, verification_mode=None):
    try:
        target = _leases.identity(report['process_pid'])
        controller = _leases.identity(controller_pid)
        if target is None or controller is None:
            raise _leases.LeaseError('browser_monitor_identity_unavailable')
        options = {'verification_mode': verification_mode} if verification_mode is not None else {}
        return _watchdog.start_monitor('browser', target, controller=controller,
                                       status_path=status_path, root=root, **options)
    except _leases.LeaseError as error:
        raise LaunchFailure(str(error)) from None


def _marker(path):
    """Atomically publish one closed, empty marker for our verified controller.

    Windows rename refuses an existing destination. Never use os.replace here:
    lifecycle requests, including existing links, must not be overwritten.
    """
    path = Path(path)
    if os.name != 'nt':
        raise LaunchFailure('windows_atomic_marker_required')
    if (not path.is_absolute() or path.parent.name != 'runs'
            or path.parent.parent.name != 'privacy-qa'
            or re.fullmatch(r'environment-browser-[1-9][0-9]{0,9}\.json\.(?:activate|stop|qa|topology|loading)', path.name) is None
            or int(path.name.split('-')[-1].split('.')[0]) > 0xffffffff):
        raise LaunchFailure('lifecycle_marker_path_invalid')
    parent = _physical(path.parent, directory=True)
    if os.path.lexists(path):
        raise FileExistsError(17, 'Existing lifecycle marker preserved', str(path))
    temporary = parent / ('.lifecycle-request-' + uuid.uuid4().hex + '.tmp')
    identity = None
    published = False

    def same_created_temporary():
        # Inspect this exact exclusive-created sibling, never follow a link or
        # delete a replacement object supplied by another actor.
        try:
            current = temporary.lstat()
        except FileNotFoundError:
            return False
        return (identity is not None and stat.S_ISREG(current.st_mode)
                and not (getattr(current, 'st_file_attributes', 0) & 0x400)
                and current.st_size == 0
                and (current.st_dev, current.st_ino) == identity)

    try:
        with temporary.open('xb') as stream:
            created = os.fstat(stream.fileno())
            identity = (created.st_dev, created.st_ino)
        # The file handle is closed before its fixed lifecycle name becomes
        # visible to the consumer, so its claim/rename cannot race our writer.
        _physical(parent, directory=True)
        if not same_created_temporary():
            raise LaunchFailure('lifecycle_temp_identity_changed')
        if os.path.lexists(path):
            raise FileExistsError(17, 'Existing lifecycle marker preserved', str(path))
        os.rename(temporary, path)
        published = True
    finally:
        if not published and identity is not None:
            _physical(parent, directory=True)
            if os.path.lexists(temporary):
                if not same_created_temporary():
                    raise LaunchFailure('lifecycle_temp_identity_changed')
                temporary.unlink()


def _owns_hold(path, token):
    try:
        return path.resolve(strict=True) == path.absolute() and path.read_text(encoding='ascii') == token
    except (OSError, UnicodeError):
        return False


def _release_hold(path, token):
    if not _owns_hold(path, token):
        raise LaunchFailure('network_hold_ownership_changed', hold_retained=path.exists())
    path.unlink()


def _ensure_hold(path, token):
    if path.exists() or path.is_symlink():
        return
    try:
        with path.open('x', encoding='ascii') as stream:
            stream.write(token)
    except FileExistsError:
        pass


def _stop_own_controller(proc, status_path, started, kind, last_report, *, timeout=12):
    if proc is None:
        return True
    if proc.poll() is None:
        try:
            _marker(Path(str(status_path) + '.stop'))
        except FileExistsError:
            pass
    deadline = time.monotonic() + timeout
    report = last_report
    while time.monotonic() < deadline:
        report = _read_status(status_path, started, kind) or report
        if proc.poll() is not None:
            child_pid = report.get('process_pid') if report else None
            # A signed child was never started only if no child PID was ever
            # reported. Otherwise verify both our controller and child stopped.
            if child_pid is None:
                # A crash after spawn but before first status is ambiguous.
                # Keep the hold; absence of a PID is not proof of no child.
                return False
            if _pid_alive(child_pid) is False:
                return True
        time.sleep(.1)
    return False


RETENTION_QA_SECONDS = 4.0
RETENTION_TOPOLOGY = ('attached', 'covered_pages', 'covered_iframes',
                      'retired_before_metadata', 'navigation_scope_resets')


def _retention_utc(value):
    if type(value) is not str or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', value):
        raise ValueError('retention_timestamp_invalid')
    parsed = dt.datetime.fromisoformat(value[:-1] + '+00:00')
    if parsed.isoformat(timespec='milliseconds').replace('+00:00', 'Z') != value:
        raise ValueError('retention_timestamp_invalid')
    return parsed.timestamp()


def _timeout_error_document(report, started, now=None):
    # Historical activation cause is not current page admission. A separate
    # fresh fixed QA below must still prove the same actual error document.
    if (type(report) is not dict or report.get('profile_scope') != 'claude-persistent'
            or report.get('activation_attempted') is not True
            or report.get('activation_complete') is not False):
        return False
    health, diagnostic = report.get('document_health'), report.get('activation_diagnostic')
    if (type(health) is not dict or type(health.get('schema')) is not int or health['schema'] != 1
            or health.get('scope') != 'activation-top-level-committed-documents-v1'
            or health.get('accepted') is not False or type(health.get('pages')) is not list
            or len(health['pages']) != 1 or type(health['pages'][0]) is not dict):
        return False
    page = health['pages'][0]
    if not (page.get('isErrorDocument') is True and page.get('unreachableDocument') is True
            and page.get('securityOriginMatchesProtected') is False
            and page.get('protectedHttpsDocument') is False and page.get('freshDocument') is True):
        return False
    if (type(diagnostic) is not dict
            or set(diagnostic) != {'schema', 'scope', 'checked_at', 'events'}
            or type(diagnostic.get('schema')) is not int or diagnostic['schema'] != 1
            or diagnostic.get('scope') != 'fixed-activation-steps-v1'
            or type(diagnostic.get('events')) is not list or not 1 <= len(diagnostic['events']) <= 64):
        return False
    try:
        current = time.time() if now is None else now
        if not (started <= _retention_utc(health['checked_at']) <= current
                and started <= _retention_utc(diagnostic['checked_at']) <= current):
            return False
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    allowed = {
        'candidates': {'started', 'ok'}, 'classify_url': {'ok'},
        'before_document': {'started', 'ok'},
        'navigation_command': {'started', 'cdp_command_timeout'},
        'document_observation': {'started', 'cdp_command_timeout', 'document_not_accepted'},
        'metadata_check': {'started', 'ok'}, 'environment_check': {'started', 'ok'},
        'complete': {'document_not_accepted'},
    }
    events = diagnostic['events']
    for event in events:
        if (type(event) is not dict or set(event) != {'stage', 'code', 'url_class'}
                or type(event.get('stage')) is not str or event['stage'] not in allowed
                or type(event.get('code')) is not str or event['code'] not in allowed[event['stage']]
                or type(event.get('url_class')) is not str
                or event['url_class'] not in ('blank', 'protected_https', 'unprotected_web', 'local', 'other', 'unavailable')):
            return False
    navigation = [event for event in events if event['stage'] == 'navigation_command']
    if ([(event['code'], event['url_class']) for event in navigation]
            != [('started', 'blank'), ('cdp_command_timeout', 'blank')]):
        return False
    observation = [(index, event) for index, event in enumerate(events)
                   if event['stage'] == 'document_observation']
    # The corrected controller retries only same-binding read observations.
    # At most seven timeouts can precede a real result; the eighth is fatal.
    if (not 2 <= len(observation) <= 9
            or observation[0][1]['code'] != 'started'
            or observation[-1][1]['code'] != 'document_not_accepted'
            or any(event['code'] != 'cdp_command_timeout' for _, event in observation[1:-1])
            or any(event['url_class'] != 'blank' for _, event in observation)
            or observation[0][0] <= next(index for index, event in enumerate(events)
                                        if event['stage'] == 'navigation_command'
                                        and event['code'] == 'cdp_command_timeout')
            or any(event['stage'] != 'document_observation'
                   for event in events[observation[0][0]:observation[-1][0] + 1])):
        return False
    # The only error is that exact initial command timeout, followed by an
    # observed error document and successful actual metadata/environment checks.
    expected = [('navigation_command', 'cdp_command_timeout'),
                ('document_observation', 'document_not_accepted'),
                ('metadata_check', 'ok'), ('environment_check', 'ok'),
                ('complete', 'document_not_accepted')]
    cursor = 0
    for event in events:
        if cursor < len(expected) and (event['stage'], event['code']) == expected[cursor]:
            cursor += 1
    return cursor == len(expected)


def _retention_validator(root):
    import importlib.util
    source = _physical(Path(root) / 'privacy-qa' / 'status_publisher.py')
    spec = importlib.util.spec_from_file_location('claude_timeout_recovery_validator', source)
    if spec is None or spec.loader is None:
        raise ValueError('retention_validator_unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_status


def _retention_topology(report):
    counts = report.get('counts', {})
    result = (report.get('configuration_generation'), *(counts.get(name) for name in RETENTION_TOPOLOGY))
    if type(result[0]) is not int or not 1 <= result[0] <= 9007199254740991:
        raise ValueError('retention_topology_invalid')
    if any(type(value) is not int or value < 0 for value in result[1:]):
        raise ValueError('retention_topology_invalid')
    return result


def _retained_session_identity(root, proc, status_path, report, original_monitor):
    if (proc is None or proc.poll() is not None or type(original_monitor) is not dict
            or original_monitor.get('kind') != 'browser'
            or not re.fullmatch('[0-9a-f]{32}', original_monitor.get('nonce', ''))):
        return None
    expected = Path(root) / 'privacy-qa' / 'runs' / f'environment-browser-{proc.pid}.json'
    if Path(status_path) != expected:
        return None
    _physical(expected)
    config_path = Path(root) / 'environment-leases' / ('monitor-' + original_monitor['nonce'] + '.config.json')
    config = _watchdog.validate_config(_leases.read_json(config_path, root), root)
    if (config.get('kind') != 'browser' or config.get('status_path') != str(expected)
            or config['controller']['pid'] != proc.pid or config['target']['pid'] != report.get('process_pid')
            or config.get('nonce') != original_monitor['nonce']):
        return None
    target, controller = config['target'], config['controller']
    active = _watchdog.active_monitor('browser', target, root=root)
    if (active is None or any(active.get(key) != original_monitor.get(key)
                             for key in ('kind', 'monitor_pid', 'registration', 'nonce'))):
        return None
    registration = _leases.read_json(Path(active['registration']), root)
    if (registration.get('source') != str(expected)
            or not _leases.same_identity(registration['target'], target)
            or registration['monitor']['pid'] != active['monitor_pid']
            or not _leases.alive(target) or not _leases.alive(controller)
            or not _leases.alive(registration['monitor'])
            or _leases.parents().get(target['pid']) != controller['pid']):
        return None
    return target, controller, registration['monitor']


def _retention_runtime(root, identities, status_path):
    # Calls the production observer afresh, including its uncached WinAPI
    # host-timezone/session checks. Navigation continuity is insufficient here.
    value = _watchdog.browser_observation(root, identities[0], identities[1], str(status_path))
    checked = value.get('runtime_checked_at')
    if (value.get('mode') != 'runtime' or type(checked) not in (int, float)
            or value.get('checked_at') != checked or not 0 <= time.time() - checked <= 4):
        raise ValueError('retention_runtime_unverified')
    return checked


def _current_single_error_qa(qa, requested, previous, now):
    if (type(qa) is not dict or type(qa.get('schema')) is not int or qa['schema'] != 1
            or qa.get('scope') != 'fixed-top-level-document-and-no-stun-rtc-v1'
            or qa.get('complete_target_inventory') is not True or qa.get('accepted') is not False
            or type(qa.get('pages')) is not list or len(qa['pages']) != 1):
        return False
    stamp = _retention_utc(qa['checked_at'])
    if not (requested <= stamp <= now and stamp > previous and 0 <= now - stamp <= 4):
        return False
    page = qa['pages'][0]
    return (type(page) is dict and page.get('isErrorDocument') is True
            and page.get('unreachableDocument') is True
            and page.get('securityOriginMatchesProtected') is False
            and page.get('protectedHttpsDocument') is False
            and page.get('mainDocumentLoaded') is False and page.get('accepted') is False
            and page.get('environmentMatches') is False and page.get('rtc') is None
            and page.get('rtcNoRawAddressObserved') is False and page.get('rtcAccepted') is False)


def _keep_protected_timeout_error(root, proc, status_path, started, kind, original_monitor):
    # Availability-only recovery. Never creates/renews a lease, changes routing,
    # sends navigation, admits an incomplete page, or removes a manual hold.
    if kind != 'browser':
        return None
    hold = Path(root) / 'hold.block'
    if hold.exists() or hold.is_symlink():
        return None
    try:
        before = _read_status(status_path, started, kind)
        if not _ready(before) or not _timeout_error_document(before, started):
            return None
        validator = _retention_validator(root)
        before = validator(before)
        topology = _retention_topology(before)
        identities = _retained_session_identity(root, proc, status_path, before, original_monitor)
        if identities is None:
            return None
        first_runtime = _retention_runtime(root, identities, status_path)
        _verified_exit(root, 17894)
        # Obtain a new controller-owned QA after the real guarded-route probe.
        previous = before.get('qa_diagnostic')
        previous_stamp = _retention_utc(previous['checked_at']) if type(previous) is dict else -1
        requested = int(time.time() * 1000) / 1000
        _marker(Path(str(status_path) + '.qa'))
        deadline = time.monotonic() + RETENTION_QA_SECONDS
        while time.monotonic() < deadline:
            if hold.exists() or hold.is_symlink() or proc.poll() is not None:
                return None
            after = _read_status(status_path, started, kind)
            if (not _ready(after) or not _timeout_error_document(after, started)
                    or after.get('process_pid') != before.get('process_pid')):
                return None
            after = validator(after)
            if (_retention_topology(after) != topology
                    or after.get('navigation_guard') is not None
                    or after.get('activation_diagnostic') != before.get('activation_diagnostic')):
                return None
            qa = after.get('qa_diagnostic')
            if (type(qa) is dict and _retention_utc(qa['checked_at']) >= requested
                    and _retention_utc(qa['checked_at']) > previous_stamp):
                if not _current_single_error_qa(qa, requested, previous_stamp, time.time()):
                    return None
                again = _retained_session_identity(root, proc, status_path, after, original_monitor)
                if again is None or not all(_leases.same_identity(a, b) for a, b in zip(identities, again)):
                    return None
                if _retention_runtime(root, again, status_path) <= first_runtime:
                    return None
                if (hold.exists() or hold.is_symlink()
                        or not 0 <= time.time() - _retention_utc(qa['checked_at']) <= 4):
                    return None
                return {'outcome': 'protected_page_unavailable', 'controller_pid': proc.pid,
                        'process_pid': after['process_pid'], 'status_path': str(status_path),
                        'retained_identity': {'process_creation': again[0]['creation'],
                                              'controller_creation': again[1]['creation']},
                        'environment_monitor': original_monitor, 'timezone': 'America/New_York', 'locale': 'en-US',
                        'document_evidence': {'document_loaded': False, 'activation_completed': False,
                            'window_preserved': True, 'startup_error': 'cdp_command_timeout',
                            'current_error_document_verified': True, 'checked_at': qa['checked_at']},
                        'warnings': list(after.get('error_codes', [])),
                        'limits': ['Protected environment and exit verified; actual Claude page remains unavailable. Fresh complete-page QA is required before reuse can report success.']}
            time.sleep(.1)
        return None
    except LaunchFailure:
        raise
    except Exception:
        return None



def launch_environment(kind, exe, argv, env, root, *, verification_mode=None):
    """Return a redacted outcome after private locale + network activation.

    Existing manual locks are never removed. On unknown shutdown the owned hold
    remains, preserving failure-closed behavior instead of weakening protection.
    """
    root = _physical(root, directory=True)
    exe = _physical(exe)
    if kind != 'browser':
        raise LaunchFailure('desktop_private_controller_not_verified')
    if verification_mode not in (None, NATIVE_BROWSER_MODE):
        raise LaunchFailure('browser_verification_mode_invalid')
    if not isinstance(env, dict):
        raise LaunchFailure('invalid_launch_configuration')
    if not isinstance(argv, (list, tuple)) or any(not isinstance(value, str) or any(c in value for c in '\0\r\n') for value in argv):
        raise LaunchFailure('invalid_launch_arguments')
    # The controller adds the sole debugging pipe. Ports and Node inspectors are
    # never supplied by this launcher or accepted from its caller.
    forbidden = ('--remote-debugging', '--inspect', '--no-sandbox', '--ignore-certificate-errors')
    if any(arg.lower().startswith(forbidden) for arg in argv):
        raise LaunchFailure('unsafe_debug_or_security_argument')
    if kind == 'browser':
        profiles = [arg.split('=', 1)[1] for arg in argv if arg.startswith('--user-data-dir=')]
        if len(profiles) != 1:
            raise LaunchFailure('isolated_browser_profile_required')
        raw_profile = Path(profiles[0])
        profile_root = root / 'browser-profiles'
        if not raw_profile.is_absolute() or not raw_profile.is_relative_to(profile_root) or '..' in raw_profile.parts:
            raise LaunchFailure('isolated_browser_profile_required')
        raw_profile.mkdir(parents=True, exist_ok=True)
        _physical(raw_profile, directory=True)
    if verification_mode == NATIVE_BROWSER_MODE and list(argv) != native_browser_arguments(root):
        raise LaunchFailure('native_browser_arguments_mismatch')
    node_value = shutil.which('node')
    if not node_value:
        raise LaunchFailure('node_runtime_unavailable')
    node = _physical(node_value)
    qa = _physical(root / 'privacy-qa', directory=True)
    controller = _physical(qa / 'claude_environment_controller.mjs')
    runs = qa / 'runs'
    runs.mkdir(exist_ok=True)
    _physical(runs, directory=True)
    hold = root / 'hold.block'
    if hold.exists() or hold.is_symlink():
        raise LaunchFailure('preexisting_network_hold_preserved', hold_retained=True)
    try:
        _verified_exit(root, 17895)
    except LaunchFailure as error:
        record_launch_failure(root,error,stage='verify_dedicated_exit')
        raise
    token = 'environment-launch-' + uuid.uuid4().hex + '\n'
    config_path = runs / ('launch-' + uuid.uuid4().hex + '.json')
    config = {'schema_version': 1, 'kind': kind, 'exe': str(exe), 'args': list(argv),
              'domains': list(DOMAINS), 'timezone': 'America/New_York', 'locale': 'en_US'}
    if verification_mode is not None:
        config['verification_mode'] = verification_mode
    proc = None
    report = None
    status_path = None
    environment_monitor = None
    started = time.time()
    stage = 'acquire_hold'
    try:
        with hold.open('x', encoding='ascii') as stream:
            stream.write(token)
        with config_path.open('x', encoding='utf-8') as stream:
            json.dump(config, stream, ensure_ascii=False)
        _physical(config_path)
        stage = 'spawn_controller'
        proc = subprocess.Popen([str(node), str(controller), '--config', str(config_path)],
                                env=dict(env), cwd=str(root), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        status_path = runs / ('environment-' + kind + '-' + str(proc.pid) + '.json')
        stage = 'wait_runtime'
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise LaunchFailure('environment_controller_exited_before_ready')
            report = _read_status(status_path, started, kind)
            if (_native_ready(report, initial=True) if verification_mode == NATIVE_BROWSER_MODE else _ready(report)):
                if _pid_alive(report['process_pid']) is not True:
                    raise LaunchFailure('environment_child_not_confirmed_running')
                break
            if _real_failure(report):
                raise LaunchFailure('environment_metadata_not_verified')
            time.sleep(.1)
        else:
            raise LaunchFailure('environment_ready_timeout')
        # Register the exact process tree and obtain a live metadata lease
        # before the caller's own startup hold can be released. This also makes
        # ordinary-PAC connections from this browser stay on the protected path.
        stage = 'register_monitor'
        options = {'verification_mode': verification_mode} if verification_mode is not None else {}
        environment_monitor = _start_browser_monitor(root, proc.pid, report, status_path, **options)
        stage = 'verify_dedicated_exit'
        _verified_exit(root, 17895)
        stage = 'release_hold'
        _release_hold(hold, token)
        stage = 'verify_gate'
        deadline = time.monotonic() + 15
        while True:
            try:
                _verified_exit(root, 17894)
                break
            except LaunchFailure:
                if time.monotonic() >= deadline:
                    raise LaunchFailure('protected_gate_not_verified') from None
                time.sleep(.2)
        if hold.exists() or hold.is_symlink():
            raise LaunchFailure('network_hold_changed_before_activation', hold_retained=True)
        stage = 'activate'
        _marker(Path(str(status_path) + '.activate'))
        stage = 'wait_activation'
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise LaunchFailure('environment_controller_exited_during_activation')
            report = _read_status(status_path, started, kind) or report
            ready = (_native_ready(report) if verification_mode == NATIVE_BROWSER_MODE else _ready(report))
            if report.get('activation_complete') is True and ready:
                if _pid_alive(report['process_pid']) is not True:
                    raise LaunchFailure('environment_child_exited_during_activation')
                if verification_mode == NATIVE_BROWSER_MODE:
                    target, owner = _leases.identity(report['process_pid']), _leases.identity(proc.pid)
                    monitor, observation = verify_native_browser_monitor(root, target, owner, status_path,
                                                                          monitor=environment_monitor)
                    return {'outcome': 'native-policy-ready', 'verification_mode': verification_mode,
                            'controller_pid': proc.pid, 'process_pid': report['process_pid'],
                            'status_path': str(status_path), 'environment_monitor': monitor,
                            'timezone': 'America/New_York', 'locale': 'en-US',
                            'environment_evidence': observation['reason'],
                            'document_evidence': {'document_loaded': None,
                                'navigation_dispatched': True, 'scope': 'policy-readiness-only'},
                            'warnings': list(report.get('error_codes', [])),
                            'limits': ['Startup metadata and no-STUN ICE were checked once; native process policy is independently monitored.',
                                'Remote document loading is not asserted by policy readiness.',
                                'Shared Edge executable: no per-profile WFP hard isolation is claimed.',
                                'Network admission still requires the independent four-second allowed-exit lease.']}
                return {'outcome': 'activated', 'controller_pid': proc.pid,
                        'process_pid': report['process_pid'], 'status_path': str(status_path),
                        'environment_monitor': environment_monitor,
                        'timezone': 'America/New_York', 'locale': 'en-US',
                        'warnings': list(report.get('error_codes', [])),
                        'limits': ['Private environment metadata verified; not a per-packet egress proof.']}
            if _real_failure(report):
                raise LaunchFailure('environment_changed_during_activation')
            time.sleep(.1)
        retained_page = (_keep_protected_timeout_error(root, proc, status_path, started, kind, environment_monitor)
                         if verification_mode is None else None)
        if retained_page is not None:
            return retained_page
        raise LaunchFailure('environment_activation_timeout')
    except Exception as error:
        # Preserve the initiating stage/status before normal rollback can turn
        # the controller snapshot into child_exited/private_pipe_unavailable.
        code = error.code if isinstance(error, LaunchFailure) else 'environment_launch_failed'
        diagnostic = _capture_failure(root,stage,code,report=report,
                                      controller_pid=proc.pid if proc else None)
        failure = LaunchFailure(code)
        # Re-establish an owned hold before requesting shutdown if activation
        # already released it. Never overwrite a user's intervening manual lock.
        rollback_error = None
        try:
            if proc is not None:
                _ensure_hold(hold, token)
            safe = _stop_own_controller(proc, status_path, started, kind, report) if proc else True
            if safe and _owns_hold(hold, token):
                _release_hold(hold, token)
        except Exception as cleanup_error:
            rollback_error = cleanup_error
            raise
        finally:
            retained = hold.exists() or hold.is_symlink()
            if diagnostic is not None:
                diagnostic['hold_retained'] = retained
            _publish_failure(root,rollback_error if rollback_error is not None else failure,diagnostic)
        failure.hold_retained = retained
        raise failure from None
    finally:
        if config_path.is_file() and not config_path.is_symlink() and config_path.resolve() == config_path.absolute():
            config_path.unlink()
