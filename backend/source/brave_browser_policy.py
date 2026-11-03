"""Actual OS/process policy for an ordinary, manually operated Brave window.

No CDP, webdriver, browser injection, canvas/WebGL alteration or CAPTCHA solving.
The independent watchdog renews proof only after a fresh native OS/argv check.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import time

MODE = 'brave_manual_browser_v1'
SCOPE = 'brave-browser-os-process-policy-v1'
ZONE = 'America/Denver'
WINDOWS_ZONE = 'Mountain Standard Time'


def require_webrtc_preferences(root):
    """Read the dedicated profile only; never substitute argv for this setting."""
    import environment_lease as leases
    path = leases.physical(Path(root) / 'browser-profiles/brave-claude/Default/Preferences', Path(root))
    if path.stat().st_size > 8 * 1024 * 1024:
        raise leases.LeaseError('manual_browser_preferences_invalid')
    value = json.loads(path.read_text(encoding='utf-8'))
    if (type(value) is not dict or type(value.get('webrtc')) is not dict
            or value['webrtc'].get('ip_handling_policy') != 'disable_non_proxied_udp'):
        raise leases.LeaseError('manual_browser_webrtc_preferences_invalid')


def prepare_webrtc_preferences(root):
    """Caller must first prove the dedicated profile is unused."""
    import environment_lease as leases
    folder = Path(root) / 'browser-profiles/brave-claude/Default'
    folder.mkdir(parents=True, exist_ok=True)
    leases.physical(folder, Path(root))
    path = folder / 'Preferences'
    if path.exists():
        leases.physical(path, Path(root))
        if path.stat().st_size > 8 * 1024 * 1024:
            raise leases.LeaseError('manual_browser_preferences_invalid')
        value = json.loads(path.read_text(encoding='utf-8'))
    else:
        value = {}
    if type(value) is not dict or type(value.get('webrtc', {})) is not dict:
        raise leases.LeaseError('manual_browser_preferences_invalid')
    if value.get('webrtc', {}).get('ip_handling_policy') != 'disable_non_proxied_udp':
        value.setdefault('webrtc', {})['ip_handling_policy'] = 'disable_non_proxied_udp'
        # Browser preferences are larger than the intentionally bounded lease
        # format. Write only after profile-unused validation by the launcher.
        import secrets
        temp = path.with_name(path.name + '.webrtc-' + secrets.token_hex(8) + '.tmp')
        try:
            with temp.open('x', encoding='utf-8', newline='\n') as handle:
                json.dump(value, handle, ensure_ascii=False, separators=(',', ':'))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
        finally:
            if temp.exists():
                temp.unlink()
    require_webrtc_preferences(root)


def arguments(root, url='about:blank'):
    if url not in ('about:blank', 'https://claude.ai/'):
        raise ValueError('manual_browser_url_not_allowed')
    return ['--user-data-dir=' + str(Path(root) / 'browser-profiles/brave-claude'),
            '--no-first-run', '--no-default-browser-check', '--disable-sync',
            '--disable-extensions', '--disable-background-networking',
            '--disable-component-update', '--disable-default-apps',
            '--proxy-server=http://127.0.0.1:17894', '--proxy-bypass-list=<-loopback>',
            '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            '--lang=en-US', '--accept-lang=en-US,en', url]


def source(value, record, now, leases):
    if (type(value) is not dict or record.get('verification_mode') != MODE
            or value.get('schema_version') != 1 or value.get('kind') != 'browser'
            or value.get('verification_mode') != MODE or value.get('environment_scope') != SCOPE
            or type(value.get('process_pid')) is not int or value['process_pid'] != record['target']['pid']
            or value.get('status') != 'monitoring' or value.get('error_codes') != []
            or value.get('page_javascript_measured') is not False
            or value.get('ice_candidates_measured') is not False):
        raise leases.LeaseError('manual_browser_source_invalid')
    baseline = value.get('native_baseline')
    if (type(baseline) is not dict or set(baseline) != {'schema', 'scope', 'checked_at', 'timezone', 'windows_timezone', 'language_preference', 'launcher_sha256', 'browser_binding_sha256'}
            or type(baseline['schema']) is not int or baseline['schema'] != 1
            or baseline['scope'] != SCOPE or baseline['timezone'] != ZONE
            or baseline['windows_timezone'] != WINDOWS_ZONE or baseline['language_preference'] != 'en-US,en'
            or not isinstance(baseline['launcher_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', baseline['launcher_sha256'])
            or not re.fullmatch('[0-9a-f]{64}', str(baseline.get('browser_binding_sha256', '')))):
        raise leases.LeaseError('manual_browser_baseline_invalid')
    checked = leases._suspension_timestamp(baseline['checked_at'])
    heartbeat = leases._suspension_timestamp(value.get('controller_heartbeat_checked_at'))
    published = leases._suspension_timestamp(value.get('at'))
    born = int(record['target']['creation'], 16) / 10000000 - 11644473600
    bootstrap = record.get('bootstrap_checked_at')
    if (type(bootstrap) not in (int, float) or not born <= checked <= bootstrap <= now
            or leases.native_startup_fingerprint(baseline) != record.get('startup_runtime_sha256')
            or not born <= checked <= heartbeat <= published <= now
            or not 0 <= now - heartbeat <= leases.TTL or not 0 <= now - published <= leases.TTL):
        raise leases.LeaseError('manual_browser_source_expired_or_changed')
    return {'bootstrap_checked_at': bootstrap, 'heartbeat_checked_at': heartbeat}


def actual_arguments(root, target, controller, leases, reader=None):
    from browser_system_timezone import WindowsProcessArgumentsReader
    api = reader or WindowsProcessArgumentsReader()
    for identity in (target, controller):
        if not leases.same_identity(identity, leases.identity(identity['pid'])):
            raise leases.LeaseError('manual_browser_identity_invalid')
    actual = api.read_arguments(target['pid'])
    if (not actual or os.path.normcase(actual[0]) != os.path.normcase(target['image'])
            or actual[1:] != arguments(root)):
        raise leases.LeaseError('manual_browser_arguments_invalid')
    owner = api.read_arguments(controller['pid'])
    rest = list(owner[1:])
    while rest and rest[0] in ('-B', '-E', '-s', '-I', '-u'):
        rest.pop(0)
    expected = str(Path(root) / 'claude_brave_launch.py')
    if (not owner or os.path.normcase(owner[0]) != os.path.normcase(controller['image'])
            or not rest or os.path.normcase(rest.pop(0)) != os.path.normcase(expected)
            or rest not in ([], ['--console'])):
        raise leases.LeaseError('manual_browser_controller_invalid')
    for identity in (target, controller):
        if not leases.same_identity(identity, leases.identity(identity['pid'])):
            raise leases.LeaseError('manual_browser_identity_invalid')
    return hashlib.sha256(json.dumps(actual, ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest()


def observation(root, target, controller, status_path, *, record=None, bootstrap=False):
    import environment_lease as leases
    from browser_system_timezone import require_eastern_system_timezone
    root = Path(root)
    expected = root / 'privacy-qa/runs' / f"environment-browser-{controller['pid']}.json"
    if (Path(status_path) != expected or not leases.alive(target) or not leases.alive(controller)
            or leases.parents().get(target['pid']) != controller['pid']):
        raise leases.LeaseError('manual_browser_identity_invalid')
    before = leases.read_json(expected, root)
    if record is None:
        baseline = before.get('native_baseline', {})
        record = {'kind': 'browser', 'verification_mode': MODE, 'target': target, 'controller': controller,
                  'bootstrap_checked_at': leases._suspension_timestamp(baseline.get('checked_at')),
                  'startup_runtime_sha256': leases.native_startup_fingerprint(baseline)}
    initial = source(before, record, time.time(), leases)
    measured, began = time.time(), time.monotonic()
    require_eastern_system_timezone(target, controller, identify=leases.identity, same_identity=leases.same_identity)
    require_webrtc_preferences(root)
    fingerprint = actual_arguments(root, target, controller, leases)
    if not bootstrap and fingerprint != record.get('native_arguments_sha256'):
        raise leases.LeaseError('manual_browser_arguments_changed')
    if (os.path.normcase(target['image']) != os.path.normcase(browser_executable(root))
            or before['native_baseline']['browser_binding_sha256'] != binding_sha(root)):
        raise leases.LeaseError('brave_runtime_binding_changed')
    expected_sha = hashlib.sha256((root / 'brave_browser_launch.py').read_bytes()).hexdigest()
    if before['native_baseline']['launcher_sha256'] != expected_sha:
        raise leases.LeaseError('manual_browser_launcher_changed')
    after = leases.read_json(expected, root)
    source(after, record, time.time(), leases)
    if (not leases.alive(target) or not leases.alive(controller)
            or leases.parents().get(target['pid']) != controller['pid']
            or not 0 <= time.time() - measured <= leases.TTL
            or not 0 <= time.monotonic() - began <= leases.TTL):
        raise leases.LeaseError('manual_browser_policy_expired')
    return {'checked_at': measured, 'reason': leases.NATIVE_BROWSER_REASON,
            'bootstrap_checked_at': measured if bootstrap else initial['bootstrap_checked_at'],
            'startup_runtime_sha256': record['startup_runtime_sha256'],
            'native_arguments_sha256': fingerprint}


def read_binding(root):
    import environment_lease as leases
    root=Path(root)
    value=leases.read_json(root/'brave-runtime.json',root)
    if (type(value) is not dict or set(value)!={'schema','browser_executable','sha256','size','mtime_ns','version','publisher_verified'}
            or value.get('schema')!=1 or value.get('publisher_verified') is not True
            or not re.fullmatch('[0-9a-f]{64}',str(value.get('sha256','')))):
        raise leases.LeaseError('brave_runtime_binding_invalid')
    expected=Path(os.environ['LOCALAPPDATA'])/'BraveSoftware/Brave-Browser/Application/brave.exe'
    if os.path.normcase(value['browser_executable'])!=os.path.normcase(str(expected)):
        raise leases.LeaseError('brave_runtime_path_invalid')
    leases.physical(expected,expected.parent)
    stat=expected.stat()
    if stat.st_size!=value['size'] or stat.st_mtime_ns!=value['mtime_ns']:
        raise leases.LeaseError('brave_updated_requires_revalidation')
    return value


def browser_executable(root):
    return read_binding(root)['browser_executable']


def binding_sha(root):
    import environment_lease as leases
    return leases.native_startup_fingerprint(read_binding(root))


def verify_binary(root):
    import environment_lease as leases
    value=read_binding(root)
    if hashlib.sha256(Path(value['browser_executable']).read_bytes()).hexdigest()!=value['sha256']:
        raise leases.LeaseError('brave_runtime_hash_changed')
