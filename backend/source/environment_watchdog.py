"""Background, process-bound environment validation for the two safe launchers.

Native polling only reads the launcher's own Live Expression in background DevTools.
Browser polling reads either a completed runtime check or the controller's
explicit, short navigation configuration-continuity proof. A heartbeat alone is
never a proof. No window activation, input or credentials.
"""
from pathlib import Path
import argparse
import ctypes as C
from ctypes import wintypes as W
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import uuid

import environment_lease as leases
from browser_system_timezone import require_eastern_system_timezone, HostTimezoneError
from native_monitor_recovery import NativeMinimizeRecovery

ROOT = Path(__file__).resolve().parent
CREATE_NO_WINDOW = 0x08000000
NAVIGATION_MAX_SECONDS = 15
NAVIGATION_FIELDS = frozenset(('schema', 'mode', 'started_at', 'checked_at',
                               'deadline_at', 'bindings_verified',
                               'first_runtime_checked_at'))
COMPLETION_FIELDS = frozenset(('schema', 'mode', 'started_at', 'deadline_at',
                              'first_runtime_checked_at', 'stopped_at',
                              'runtime_checked_at'))
MAX_NAVIGATION_COMPLETIONS = 16
_NATIVE_RTC_MODULES = {}


def native_rtc_policy_module(root):
    """Load only the manifest-bound physical controller, never an ambient name."""
    root = Path(root)
    folder = leases.physical(root / 'native-launcher', root)
    path = leases.physical(folder / 'native_rtc_policy.py', root)
    manifest = leases.read_json(folder / 'native-rtc-manifest.json', root)
    if (type(manifest) is not dict or set(manifest) != {'schema','runtime_sha256','module_sha256'}
            or type(manifest.get('schema')) is not int or manifest['schema'] != 1
            or any(type(manifest.get(k)) is not str or not re.fullmatch('[0-9a-f]{64}', manifest[k])
                   for k in ('runtime_sha256','module_sha256'))):
        raise leases.LeaseError('native_rtc_manifest_invalid')
    source = path.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if len(source) > 131072 or digest != manifest['module_sha256']:
        raise leases.LeaseError('native_rtc_source_changed')
    key = (str(path), digest)
    module = _NATIVE_RTC_MODULES.get(key)
    if module is None:
        spec = importlib.util.spec_from_file_location('claude_native_rtc_policy_' + digest, path)
        if spec is None or spec.loader is None:
            raise leases.LeaseError('native_rtc_module_invalid')
        module = importlib.util.module_from_spec(spec)
        # Execute the exact bytes just hashed; exec_module would reread the file.
        exec(compile(source, str(path), 'exec'), module.__dict__)
        _NATIVE_RTC_MODULES[key] = module
    module.pins(root, leases)  # Includes the controller's own loaded-source binding.
    return module


def require_native_browser_arguments(*args,**kwargs):
    # Imported only by the explicit new mode; legacy/desktop installations do
    # not depend on this new helper merely to import their unchanged verifier.
    from browser_system_timezone import require_native_browser_arguments as check
    return check(*args,**kwargs)


def native_browser_policy_observation(root,target,controller,status_path,*,record=None,bootstrap=False):
    expected=Path(root)/'privacy-qa'/'runs'/f"environment-browser-{controller['pid']}.json"
    if (Path(status_path)!=expected or not leases.alive(target) or not leases.alive(controller)
            or leases.parents().get(target['pid'])!=controller['pid']):
        raise leases.LeaseError('native_browser_identity_invalid')
    before=leases.read_json(expected,root)
    if record is None:
        startup=before.get('startup_runtime',{})
        first=_utc_timestamp(before.get('startup_runtime_checked_at'))
        record={'kind':'browser','verification_mode':leases.NATIVE_BROWSER_MODE,'target':target,
                'controller':controller,'bootstrap_checked_at':first,
                'startup_runtime_sha256':leases.native_startup_fingerprint(startup)}
    if (record.get('verification_mode')!=leases.NATIVE_BROWSER_MODE
            or not leases.same_identity(record.get('target'),target)
            or not leases.same_identity(record.get('controller'),controller)):
        raise leases.LeaseError('native_browser_registration_invalid')
    initial=leases.native_browser_source(before,record,time.time())
    if bootstrap and not 0<=time.time()-initial['bootstrap_checked_at']<=leases.TTL:
        raise leases.LeaseError('native_browser_startup_expired')
    # This timestamp belongs to a new actual native observation, not to the
    # producer's historical JS result or a file/status publication heartbeat.
    measured=time.time(); began=time.monotonic()
    try:
        require_eastern_system_timezone(target,controller,identify=leases.identity,
                                        same_identity=leases.same_identity)
        arguments=require_native_browser_arguments(target,controller,root=root,
            identify=leases.identity,same_identity=leases.same_identity)
    except Exception:
        raise leases.LeaseError('native_browser_process_policy_invalid') from None
    fingerprint=arguments.get('arguments_sha256') if type(arguments) is dict else None
    if (type(fingerprint) is not str or re.fullmatch('[0-9a-f]{64}',fingerprint) is None
            or (not bootstrap and fingerprint!=record.get('native_arguments_sha256'))):
        raise leases.LeaseError('native_browser_arguments_changed')
    after=leases.read_json(expected,root)
    leases.native_browser_source(after,record,time.time())
    if (not leases.alive(target) or not leases.alive(controller)
            or leases.parents().get(target['pid'])!=controller['pid']
            or not 0<=time.time()-measured<=leases.TTL
            or not 0<=time.monotonic()-began<=leases.TTL
            or (bootstrap and not 0<=time.time()-initial['bootstrap_checked_at']<=leases.TTL)):
        raise leases.LeaseError('native_browser_policy_check_expired')
    return {'checked_at':measured,'reason':leases.NATIVE_BROWSER_REASON,
            'bootstrap_checked_at':initial['bootstrap_checked_at'],
            'startup_runtime_sha256':record['startup_runtime_sha256'],
            'native_arguments_sha256':fingerprint}


def good_metadata(value, nonce, now=None):
    now = time.time() if now is None else now
    return (isinstance(value, dict) and value.get('nonce') == nonce
            and value.get('origin') == 'https://claude.ai' and value.get('topFrame') is True
            and value.get('timeZone') == 'America/New_York' and value.get('language') == 'en-US'
            and value.get('januaryOffset') == 300 and value.get('julyOffset') == 240
            and type(value.get('epoch')) in (int, float)
            and 0 <= now - value['epoch'] / 1000 <= leases.TTL)


def helper_path(root):
    folder = Path(root) / 'native-launcher'
    manifest = leases.read_json(folder / 'helper-manifest.json', root)
    exe = leases.physical(folder / 'DevToolsUi.exe', root)
    if (manifest.get('schema_version') != 1 or manifest.get('helper_executable') != exe.name
            or hashlib.sha256(exe.read_bytes()).hexdigest() != manifest.get('sha256')):
        raise leases.LeaseError('monitor_helper_hash_invalid')
    return exe


def native_check(root, target, nonce):
    exe = helper_path(root)
    result = subprocess.run([str(exe), 'poll-live', str(target['pid']), target['creation'], nonce],
                            capture_output=True, text=True, encoding='utf-8-sig',
                            timeout=8, creationflags=CREATE_NO_WINDOW)
    if len(result.stdout) > 32768 or result.returncode:
        raise leases.LeaseError('native_environment_unavailable')
    value = json.loads(result.stdout)
    if (value.get('ok') is not True or value.get('command') != 'poll-live'
            or value.get('pid') != target['pid'] or not good_metadata(value.get('data'), nonce)):
        raise leases.LeaseError('native_environment_not_verified')
    # Neither observation may renew the other's timestamp. A frozen native
    # policy writer or a stale DevTools pin closes the same four-second lease.
    rtc_epoch = native_rtc_policy_module(root).verify(root, target, nonce, leases)
    return min(value['data']['epoch'] / 1000, rtc_epoch)


def _utc_timestamp(value):
    """Only the producer's explicit UTC ISO format is a timestamp."""
    if (type(value) is not str or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', value)):
        raise leases.LeaseError('browser_environment_timestamp_invalid')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.timestamp()
    except (ValueError, OverflowError, OSError):
        raise leases.LeaseError('browser_environment_timestamp_invalid') from None


def _browser_completions(value, created, now):
    """Validate the bounded, persistent record of genuinely finished loads."""
    entries = value.get('navigation_completions', [])
    if type(entries) is not list or len(entries) > MAX_NAVIGATION_COMPLETIONS:
        raise leases.LeaseError('browser_navigation_completions_invalid')
    result = []
    for item in entries:
        if (type(item) is not dict or set(item) != COMPLETION_FIELDS
                or type(item.get('schema')) is not int or item['schema'] != 1
                or item.get('mode') != 'navigation_completed_runtime'):
            raise leases.LeaseError('browser_navigation_completion_invalid')
        started, deadline, first, stopped, runtime = (
            _utc_timestamp(item[name]) for name in ('started_at', 'deadline_at',
                                                   'first_runtime_checked_at', 'stopped_at',
                                                   'runtime_checked_at'))
        # The original deadline can still be in the future when a load finishes
        # early. It remains bounded by its original start and is never renewed.
        if (not created <= first <= started <= stopped <= runtime <= now
                or not started <= deadline <= started + NAVIGATION_MAX_SECONDS
                or not 0 <= started - first <= leases.TTL):
            raise leases.LeaseError('browser_navigation_completion_time_invalid')
        result.append({'phase': (started, deadline, first), 'stopped_at': stopped,
                       'runtime_checked_at': runtime})
    return result



WORKER_NAVIGATION_FIELDS = frozenset(('schema', 'mode', 'navigation_started_at',
    'navigation_checked_at', 'navigation_deadline_at', 'first_runtime_checked_at',
    'configuration_generation', 'worker_count', 'inherited_worker_count',
    'min_runtime_checked_at', 'bindings_verified'))


def _canonical_worker_timestamp(value):
    if (type(value) is not str or len(value) != 24 or not value.endswith('Z')
            or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', value) is None):
        raise leases.LeaseError('browser_worker_evidence_timestamp_invalid')
    parsed = _utc_timestamp(value)
    if dt.datetime.fromisoformat(value[:-1] + '+00:00').isoformat(timespec='milliseconds').replace('+00:00', 'Z') != value:
        raise leases.LeaseError('browser_worker_evidence_timestamp_invalid')
    return parsed


def _worker_navigation_evidence(value, nav, counts, created, now):
    """A historical worker warning alone never grants navigation continuity."""
    item = value.get('worker_navigation_evidence')
    if (type(item) is not dict or set(item) != WORKER_NAVIGATION_FIELDS
            or type(nav) is not dict
            or type(item.get('schema')) is not int or item['schema'] != 1
            or item.get('mode') != 'fresh_worker_runtime_same_navigation'
            or item.get('bindings_verified') is not True
            or type(value.get('configuration_generation')) is not int
            or not 1 <= value['configuration_generation'] <= 9007199254740991
            or type(item.get('configuration_generation')) is not int
            or item['configuration_generation'] != value['configuration_generation']
            or type(item.get('worker_count')) is not int or not 1 <= item['worker_count'] <= 64
            or type(item.get('inherited_worker_count')) is not int
            or not 1 <= item['inherited_worker_count'] <= item['worker_count']
            or type(counts.get('workers_inherited_verified')) is not int
            or counts['workers_inherited_verified'] < item['inherited_worker_count']):
        return False
    mapping = (('navigation_started_at', 'started_at'), ('navigation_checked_at', 'checked_at'),
               ('navigation_deadline_at', 'deadline_at'), ('first_runtime_checked_at', 'first_runtime_checked_at'))
    try:
        for field, nav_field in mapping:
            _canonical_worker_timestamp(item[field])
            if item[field] != nav.get(nav_field):
                return False
        checked = _canonical_worker_timestamp(item['navigation_checked_at'])
        minimum = _canonical_worker_timestamp(item['min_runtime_checked_at'])
    except leases.LeaseError:
        return False
    return created <= minimum <= now and 0 <= now - minimum <= leases.TTL


UNPAUSED_RETIREMENT_FIELDS = frozenset(('schema', 'mode', 'checked_at',
    'configuration_generation', 'early_unpaused_total', 'retired_unpaused_verified',
    'live_unpaused_count', 'inventory_complete', 'navigation_started_at',
    'navigation_checked_at'))


def _retired_unpaused_evidence(value, nav, counts, created, now):
    """Only fresh exact-inventory proof can account for retired unpaused targets.

    The initial unpaused page remains the sole live historical exception.
    Extra live/unaccounted targets, changed generations and stale proofs fail.
    """
    item = value.get('unpaused_retirement_evidence')
    if (type(item) is not dict or set(item) != UNPAUSED_RETIREMENT_FIELDS
            or type(nav) is not dict
            or type(item.get('schema')) is not int or item['schema'] != 1
            or item.get('mode') != 'retired_unpaused_absent_from_root_inventory'
            or item.get('inventory_complete') is not True
            or type(value.get('configuration_generation')) is not int
            or not 1 <= value['configuration_generation'] <= 9007199254740991
            or type(item.get('configuration_generation')) is not int
            or item['configuration_generation'] != value['configuration_generation']):
        return False
    total, retired, live = (item.get(k) for k in
        ('early_unpaused_total', 'retired_unpaused_verified', 'live_unpaused_count'))
    if (type(total) is not int or not 2 <= total <= 4096
            or type(retired) is not int or not 1 <= retired <= total
            or type(live) is not int or live not in (0, 1) or total != retired + live
            or type(counts.get('early_unpaused_targets')) is not int
            or counts['early_unpaused_targets'] != total
            or type(counts.get('unpaused_retired_verified')) is not int
            or counts['unpaused_retired_verified'] != retired):
        return False
    try:
        for field, nav_field in (('navigation_started_at', 'started_at'),
                                 ('navigation_checked_at', 'checked_at')):
            _canonical_worker_timestamp(item[field])
            if item[field] != nav.get(nav_field):
                return False
        checked = _canonical_worker_timestamp(item['checked_at'])
        if item['checked_at'] != item['navigation_checked_at']:
            return False
    except leases.LeaseError:
        return False
    return created <= checked <= now and 0 <= now - checked <= leases.TTL


def _initial_unpaused_or_retired_proof(value, nav, counts, created, now):
    # A malformed supplied proof is never bypassed by the legacy branch.
    if 'unpaused_retirement_evidence' in value:
        return _retired_unpaused_evidence(value, nav, counts, created, now)
    return (type(counts.get('early_unpaused_targets')) is int
            and counts['early_unpaused_targets'] == 1)


VERIFIED_SCOPE_NAVIGATION_FIELDS = frozenset(('schema', 'mode', 'checked_at',
    'configuration_generation', 'scope_target_count', 'previously_verified_target_count',
    'early_unpaused_total', 'retired_unpaused_verified', 'live_unpaused_count',
    'inventory_complete', 'bindings_verified', 'baseline_scope_fingerprint',
    'current_scope_fingerprint', 'navigation_started_at', 'navigation_checked_at',
    'navigation_deadline_at', 'first_runtime_checked_at'))


def _verified_scope_navigation_evidence(value, nav, counts, created, now):
    """Validate a new, exact fully measured scope proof, never a count waiver.

    The private controller owns the session/target map and attests its fresh
    root inventory matches the exact pre-navigation measured map. Fingerprints
    bind that identity; the monitor additionally pins it for the whole original
    navigation phase. This does not assert page JavaScript ran while loading.
    """
    item = value.get('verified_scope_navigation_evidence')
    if (type(item) is not dict or set(item) != VERIFIED_SCOPE_NAVIGATION_FIELDS
            or type(nav) is not dict or set(nav) != NAVIGATION_FIELDS
            or type(nav.get('schema')) is not int or nav['schema'] != 1
            or nav.get('mode') != 'known_navigation_configuration'
            or nav.get('bindings_verified') is not True
            or type(item.get('schema')) is not int or item['schema'] != 1
            or item.get('mode') != 'complete_verified_scope_same_navigation_v1'
            or item.get('inventory_complete') is not True
            or item.get('bindings_verified') is not True
            or type(value.get('configuration_generation')) is not int
            or not 1 <= value['configuration_generation'] <= 9007199254740991
            or type(item.get('configuration_generation')) is not int
            or item['configuration_generation'] != value['configuration_generation']):
        return None
    scope, previous, total, retired, live = (item.get(key) for key in
        ('scope_target_count', 'previously_verified_target_count',
         'early_unpaused_total', 'retired_unpaused_verified', 'live_unpaused_count'))
    if (any(type(number) is not int for number in (scope, previous, total, retired, live))
            or not 1 <= scope <= 4096 or previous != scope
            or not 1 <= total <= 4096 or not 0 <= retired <= total
            or not 0 <= live <= scope or total != retired + live
            or type(counts.get('early_unpaused_targets')) is not int
            or counts['early_unpaused_targets'] != total
            or type(counts.get('unpaused_retired_verified')) is not int
            or counts['unpaused_retired_verified'] != retired):
        return None
    baseline, current = (item.get(key) for key in
                         ('baseline_scope_fingerprint', 'current_scope_fingerprint'))
    if (type(baseline) is not str or re.fullmatch(r'[0-9a-f]{64}', baseline) is None
            or type(current) is not str or current != baseline):
        return None
    mapping = (('navigation_started_at', 'started_at'),
               ('navigation_checked_at', 'checked_at'),
               ('navigation_deadline_at', 'deadline_at'),
               ('first_runtime_checked_at', 'first_runtime_checked_at'))
    try:
        for field, nav_field in mapping:
            _canonical_worker_timestamp(item[field])
            if item[field] != nav.get(nav_field):
                return None
        checked = _canonical_worker_timestamp(item['checked_at'])
        if item['checked_at'] != item['navigation_checked_at']:
            return None
        started, deadline, first = (_canonical_worker_timestamp(item[key]) for key in
            ('navigation_started_at', 'navigation_deadline_at', 'first_runtime_checked_at'))
    except leases.LeaseError:
        return None
    if (not created <= first <= started <= checked <= now <= deadline
            or not started <= deadline <= started + NAVIGATION_MAX_SECONDS
            or not 0 <= started - first <= leases.TTL
            or not 0 <= now - checked <= leases.TTL):
        return None
    return (baseline, item['configuration_generation'], scope, total, retired, live)


def browser_observation(root, target, controller, status_path, *, navigation_state=None):
    """Keep runtime evidence distinct from bounded navigation continuity.

    The controller alone owns the private CDP session/target/configuration map.
    Its navigation assertion must come from a fresh browser-root target listing
    of that unchanged, previously runtime-verified map. It does not assert that
    page Javascript executed during the navigation pause.
    """
    if not leases.alive(controller):
        raise leases.LeaseError('browser_controller_not_alive')
    expected = Path(root) / 'privacy-qa' / 'runs' / f"environment-browser-{controller['pid']}.json"
    if Path(status_path) != expected:
        raise leases.LeaseError('browser_status_path_invalid')
    value = leases.read_json(expected, root)
    counts = value.get('counts', {})
    if (type(value.get('schema_version')) is not int or value['schema_version'] != 1
            or value.get('kind') != 'browser'
            or type(value.get('process_pid')) is not int or value['process_pid'] != target['pid']
            or value.get('environment_scope') != 'isolated-browser-all-web-targets-v1'
            or value.get('status') in ('stopping', 'stopped', 'child_exited',
                                       'child_shutdown_not_confirmed', 'environment_failed')
            or not isinstance(counts, dict)
            or any(counts.get(name, 0)
                   for name in ('metadata_mismatches', 'command_errors', 'workers_unverified'))):
        raise leases.LeaseError('browser_environment_not_verified')
    runtime_checked = _utc_timestamp(value.get('environment_check_at'))
    created = max(int(item['creation'], 16) / 10000000 - 11644473600 for item in (controller, target))
    # Take the clock after the atomic read: a producer may complete a real
    # check during file IO. Sampling before that read can fabricate a future.
    now = time.time()
    if runtime_checked < created or runtime_checked > now:
        raise leases.LeaseError('browser_environment_check_expired')
    # Read Win32 state now in this exact browser observation, not from Node
    # or a cached status field. This never refreshes runtime_checked or phase.
    try:
        require_eastern_system_timezone(target, controller, identify=leases.identity,
                                        same_identity=leases.same_identity)
    except HostTimezoneError as error:
        raise leases.LeaseError(error.code) from None
    except Exception:
        raise leases.LeaseError('browser_system_timezone_unavailable') from None
    # A slow API call or clock adjustment must not preserve a stale grant.
    now = time.time()
    if runtime_checked < created or runtime_checked > now:
        raise leases.LeaseError('browser_environment_check_expired')
    completions = _browser_completions(value, created, now)
    nav = value.get('navigation_guard')
    scope_identity = None
    if 'verified_scope_navigation_evidence' in value:
        scope_identity = _verified_scope_navigation_evidence(value, nav, counts, created, now)
        # A malformed new proof never falls back to the old one-page exception,
        # nor to a still-fresh runtime timestamp from before its invalidation.
        if scope_identity is None:
            raise leases.LeaseError('browser_verified_scope_navigation_invalid')
        if ('unpaused_retirement_evidence' in value
                and not _retired_unpaused_evidence(value, nav, counts, created, now)):
            raise leases.LeaseError('browser_verified_scope_navigation_invalid')
    explicit_navigation = value.get('environment_check_pending') is True and nav is not None
    if (not explicit_navigation and value.get('environment_check_ok') is True
            and 0 <= now - runtime_checked <= leases.TTL):
        # A completed non-pending sweep after the guard disappears is the only
        # reset point. A real check during the same loading phase does not let
        # its original deadline slide forward.
        if (navigation_state is not None and nav is None
                and value.get('environment_check_pending') is False):
            navigation_state.clear()
        elif navigation_state and value.get('environment_check_pending') is False:
            # A 200 ms observer can miss the instant between two independent
            # loads. The persistent completion ring proves that the old pinned
            # load ended and a real full runtime sweep followed its stop event.
            old_phase = navigation_state.get('phase')
            if any(item['phase'] == old_phase and item['runtime_checked_at'] <= runtime_checked
                   for item in completions):
                navigation_state.clear()
        return {'checked_at': runtime_checked, 'runtime_checked_at': runtime_checked,
                'mode': 'runtime', 'reason': 'verified'}
    # A pending phase with an explicit guard hands over immediately, while the
    # original runtime grant may still be fresh. Waiting for its expiry creates
    # a poll-sized gap in which gate can expire the previous runtime lease.
    # An invalid explicit guard never falls back to that older runtime grant.
    codes = value.get('error_codes', [])
    healthy_status = (value.get('status') == 'monitoring' and type(codes) is list and not codes)
    # Edge creates its initial empty page before root auto-attach is installed.
    # The legacy exception remains one live historical target. The separately
    # versioned full-scope proof binds every measured target instead of lifting
    # that old limit or accepting any other warning/failure.
    initial_page_warning = (
        value.get('status') == 'partial' and type(codes) is list
        and codes == ['early_unpaused_target']
        and (scope_identity is not None
             or _initial_unpaused_or_retired_proof(value, nav, counts, created, now)))
    verified_worker_warning = (
        value.get('status') == 'partial' and type(codes) is list
        and codes == ['early_unpaused_target', 'worker_override_unavailable']
        and (scope_identity is not None
             or _initial_unpaused_or_retired_proof(value, nav, counts, created, now))
        and _worker_navigation_evidence(value, nav, counts, created, now))
    if (value.get('environment_check_pending') is not True
            or type(value.get('environment_check_ok')) is not bool
            or value.get('last_environment_diagnostic') != 'navigation_configuration_pending'
            or not (healthy_status or initial_page_warning or verified_worker_warning)
            or type(nav) is not dict or set(nav) != NAVIGATION_FIELDS
            or type(nav.get('schema')) is not int or nav['schema'] != 1
            or nav.get('mode') != 'known_navigation_configuration'
            or nav.get('bindings_verified') is not True
            or any(type(counts.get(name)) is not int or counts[name] != 0
                   for name in ('metadata_mismatches', 'command_errors', 'workers_unverified'))
            or any(name in counts and (type(counts[name]) is not int or counts[name] != 0)
                   for name in ('unprotected_targets', 'unknown_target_types'))
            or ('environment_check_failures' in counts and
                (type(counts['environment_check_failures']) is not int
                 or counts['environment_check_failures'] != 0))):
        raise leases.LeaseError('browser_navigation_not_verified')
    started, checked, deadline, first_runtime = (
        _utc_timestamp(nav[name]) for name in ('started_at', 'checked_at', 'deadline_at',
                                              'first_runtime_checked_at'))
    if (not created <= first_runtime <= runtime_checked <= checked <= now
            or not first_runtime <= started <= checked
            or not started <= now <= deadline <= started + NAVIGATION_MAX_SECONDS
            or not 0 <= started - first_runtime <= leases.TTL
            or not 0 <= now - checked <= leases.TTL):
        raise leases.LeaseError('browser_navigation_check_expired')
    phase = (started, deadline, first_runtime)
    if navigation_state is not None:
        same_phase = navigation_state.get('phase') == phase
        if navigation_state and navigation_state.get('phase') != phase:
            old_phase = navigation_state.get('phase')
            completed_prior = (
                isinstance(old_phase, tuple) and len(old_phase) == 3 and started > old_phase[0]
                and any(item['phase'] == old_phase
                        and item['runtime_checked_at'] <= first_runtime
                        for item in completions))
            if not completed_prior:
                raise leases.LeaseError('browser_navigation_phase_changed')
        if same_phase and navigation_state.get('verified_scope_identity') != scope_identity:
            raise leases.LeaseError('browser_navigation_scope_changed')
        navigation_state['phase'] = phase
        if scope_identity is not None:
            navigation_state['verified_scope_identity'] = scope_identity
        else:
            navigation_state.pop('verified_scope_identity', None)
    return {'checked_at': checked, 'runtime_checked_at': runtime_checked,
            'first_runtime_checked_at': first_runtime,
            'mode': 'navigation_configuration_continuity',
            'reason': 'navigation_configuration_continuity'}


def browser_check(root, target, controller, status_path):
    """Compatibility timestamp API; monitor code keeps the observation mode."""
    return browser_observation(root, target, controller, status_path)['checked_at']


def browser_transition_observation(root, target, controller, status_path, *, record=None,
                                   suspension_state=None):
    """Identify a short scope transition without granting any network access.

    The original completed runtime timestamp is retained. This evidence may
    keep a TCP socket paused; it is never an `ok=True` environment lease.
    """
    expected = Path(root) / 'privacy-qa' / 'runs' / f"environment-browser-{controller['pid']}.json"
    if Path(status_path) != expected or not leases.alive(controller) or not leases.alive(target):
        raise leases.LeaseError('browser_transition_not_suspendable')
    if leases.parents().get(target['pid']) != controller['pid']:
        raise leases.LeaseError('browser_transition_not_suspendable')
    value = leases.read_json(expected, root)
    if value.get('suspension_guard') is not None:
        if (type(record) is not dict or record.get('kind') != 'browser'
                or record.get('source') != str(expected)
                or not leases.same_identity(record['target'], target)
                or not leases.alive(record['monitor'])):
            raise leases.LeaseError('browser_suspension_source_invalid')
        guard = value['suspension_guard']
        current = leases.suspension_source(value, record, guard, time.time())
        try:
            require_eastern_system_timezone(target, controller, identify=leases.identity,
                                            same_identity=leases.same_identity)
        except Exception:
            raise leases.LeaseError('browser_transition_not_suspendable') from None
        after = leases.read_json(expected, root)
        fresh = leases.suspension_source(after, record, guard, time.time(), allow_recovered=True)
        if (not leases.alive(target) or not leases.alive(controller)
                or not leases.alive(record['monitor']) or leases.parents().get(target['pid']) != controller['pid']):
            raise leases.LeaseError('browser_transition_not_suspendable')
        # Recheck time after every potentially slow native/process operation.
        fresh = leases.suspension_source(after, record, guard, time.time(), allow_recovered=True)
        if suspension_state is not None:
            if suspension_state and suspension_state.get('phase') != current['phase']:
                raise leases.LeaseError('browser_suspension_phase_changed')
            suspension_state['phase'] = current['phase']
        selected = guard if fresh.get('recovered') else after['suspension_guard']
        return {'checked_at': leases._suspension_timestamp(selected['first_runtime_checked_at']),
                'reason': 'browser_scope_suspension_pending', 'suspension_guard': dict(selected)}
    counts, codes = value.get('counts'), value.get('error_codes')
    if (type(value.get('schema_version')) is not int or value['schema_version'] != 1
            or value.get('kind') != 'browser' or type(value.get('process_pid')) is not int
            or value['process_pid'] != target['pid']
            or value.get('environment_scope') != 'isolated-browser-all-web-targets-v1'
            or value.get('activation_complete') is not True
            or value.get('environment_check_ok') is not False
            or value.get('environment_check_pending') is not True
            or value.get('navigation_guard') is not None
            or value.get('last_environment_diagnostic') not in ('scope_changed', 'configuration_changed')
            or not ((value.get('status') == 'monitoring' and codes == [])
                    or (value.get('status') == 'partial' and codes == ['early_unpaused_target']))
            or type(counts) is not dict
            or any(type(counts.get(name)) is not int or counts[name] != 0 for name in
                   ('metadata_mismatches', 'command_errors', 'workers_unverified',
                    'unprotected_targets', 'unknown_target_types', 'environment_check_failures'))):
        raise leases.LeaseError('browser_transition_not_suspendable')
    checked, published = _utc_timestamp(value.get('environment_check_at')), _utc_timestamp(value.get('at'))
    created = max(int(item['creation'], 16) / 10000000 - 11644473600 for item in (controller, target))
    now = time.time()
    if not created <= checked <= published <= now or not 0 <= now - checked <= leases.TTL:
        raise leases.LeaseError('browser_transition_not_suspendable')
    try:
        require_eastern_system_timezone(target, controller, identify=leases.identity,
                                        same_identity=leases.same_identity)
    except Exception:
        raise leases.LeaseError('browser_transition_not_suspendable') from None
    now = time.time()
    if (not created <= checked <= published <= now or not 0 <= now - checked <= leases.TTL
            or not leases.alive(target) or not leases.alive(controller)
            or leases.parents().get(target['pid']) != controller['pid']):
        raise leases.LeaseError('browser_transition_not_suspendable')
    return {'checked_at': checked, 'reason': 'browser_scope_transition_pending'}


def validate_config(value, root):
    if not isinstance(value, dict) or value.get('schema') != 1:
        raise leases.LeaseError('monitor_config_invalid')
    kind, target, nonce = value.get('kind'), leases.validate_identity(value.get('target')), value.get('nonce')
    if value.get('verification_mode') is not None and (kind!='browser' or value['verification_mode']!=leases.NATIVE_BROWSER_MODE):
        raise leases.LeaseError('native_browser_mode_invalid')
    leases.paths(kind, target, nonce, root)
    runtime = leases.read_json(Path(root) / 'environment-runtime.json', root)
    if kind == 'browser':
        controller = leases.validate_identity(value.get('controller'))
        if (os.path.normcase(target['image']) != os.path.normcase(runtime['browser_executable'])
                or os.path.normcase(controller['image']) != os.path.normcase(runtime['node_executable'])
                or not leases.alive(controller)
                or leases.parents().get(target['pid']) != controller['pid']):
            raise leases.LeaseError('browser_controller_identity_invalid')
    elif kind == 'native':
        installed = leases.read_json(Path(root) / 'installed.json', root)
        package = installed.get('package_full_name', installed.get('package', ''))
        windows_apps = Path(os.environ['ProgramFiles']) / 'WindowsApps'
        expected = windows_apps / package / 'app' / 'Claude.exe'
        if (not package or os.path.normcase(os.path.abspath(target['image']))
                != os.path.normcase(os.path.abspath(expected))):
            raise leases.LeaseError('native_image_not_registered')
    return value


def run_monitor(config_path, root=ROOT):
    value = validate_config(leases.read_json(config_path, root), root)
    kind, target, nonce = value['kind'], value['target'], value['nonce']
    native_browser=kind=='browser' and value.get('verification_mode')==leases.NATIVE_BROWSER_MODE
    monitor = leases.identity(os.getpid())
    navigation_state = {}
    suspension_state = {}
    def still_current_native():
        try:
            record = leases.read_json(record_path, root)
            return (record.get('nonce') == nonce and leases.same_identity(record['target'], target)
                    and leases.same_identity(record['monitor'], monitor)
                    and record.get('source') == source and leases.alive(target))
        except Exception:
            return False
    recovery = (NativeMinimizeRecovery(target, nonce, helper=lambda: helper_path(root),
                                      alive=leases.alive, still_current=still_current_native)
                if kind == 'native' else None)
    observation = (native_browser_policy_observation(root,target,value['controller'],value['status_path'],bootstrap=True)
                   if native_browser else {'checked_at': native_check(root, target, nonce), 'reason': 'verified'}
                   if kind == 'native' else browser_observation(
                       root, target, value['controller'], value['status_path'],
                       navigation_state=navigation_state))
    # A replacement monitor must bootstrap from fresh, real runtime evidence;
    # an old navigation baseline can never create a new registration.
    if observation['reason'] != (leases.NATIVE_BROWSER_REASON if native_browser else 'verified'):
        raise leases.LeaseError('browser_monitor_requires_runtime_bootstrap')
    source = (value.get('status_path') if kind == 'browser' else
              'native-helper-sha256:' + hashlib.sha256(helper_path(root).read_bytes()).hexdigest())
    record_path, lease_path = leases.register(kind, target, monitor, nonce,
                                             source=source, root=root,
                                             initial_checked_at=observation['checked_at'],
        **({'verification_mode':leases.NATIVE_BROWSER_MODE,'controller':value['controller'],
            'bootstrap_checked_at':observation['bootstrap_checked_at'],
            'startup_runtime_sha256':observation['startup_runtime_sha256'],
            'native_arguments_sha256':observation['native_arguments_sha256']} if native_browser else {}))
    while True:
        try:
            record = leases.read_json(record_path, root)
            if record.get('nonce') != nonce or not leases.same_identity(record['monitor'], monitor):
                return  # Replaced by a newer verified one-click transaction.
            if record.get('verification_mode')!=value.get('verification_mode'):
                return
            if not leases.alive(target):
                return  # The gateway also independently checks this identity.
            observation = (native_browser_policy_observation(root,target,value['controller'],value['status_path'],record=record)
                           if native_browser else {'checked_at': native_check(root, target, nonce), 'reason': 'verified'}
                           if kind == 'native' else browser_observation(
                               root, target, value['controller'], value['status_path'],
                               navigation_state=navigation_state))
            if kind == 'browser' and observation['reason'] == 'verified':
                suspension_state.clear()
            leases.write_lease(record_path, lease_path, nonce, True, observation['checked_at'],
                               reason=observation['reason'], root=root)
            if recovery is not None:
                recovery.verified()
        except leases.LeaseError as e:
            if str(e) == 'lease_superseded':
                return
            revoked = False
            try:
                failed_at, reason, observed_ok, pending_guard = time.time(), str(e), False, None
                # Only the narrow, currently healthy browser scope transition
                # can request transport suspension. It remains a false lease.
                if kind == 'browser' and reason in ('browser_navigation_not_verified', 'browser_navigation_check_expired'):
                    # The controller may complete its real runtime check
                    # between the failed observation and the classification
                    # read. Retry exactly once using the ordinary verifier;
                    # never write a false lease for that already-valid result.
                    try:
                        fresh = browser_observation(root, target, value['controller'],
                            value['status_path'], navigation_state=navigation_state)
                        if fresh['reason'] not in ('verified', 'navigation_configuration_continuity'):
                            raise leases.LeaseError('environment_check_unavailable')
                        failed_at, reason, observed_ok = fresh['checked_at'], fresh['reason'], True
                        if reason == 'verified':
                            suspension_state.clear()
                    except leases.LeaseError as latest:
                        if str(latest) == 'lease_superseded':
                            return
                        failed_at, reason = time.time(), str(latest)
                    except Exception:
                        failed_at, reason = time.time(), 'environment_check_unavailable'
                if kind == 'browser' and not observed_ok and reason in ('browser_navigation_not_verified', 'browser_navigation_check_expired'):
                    try:
                        pending = browser_transition_observation(root, target, value['controller'], value['status_path'],
                            record=record, suspension_state=suspension_state)
                        failed_at, reason = pending['checked_at'], pending['reason']
                        pending_guard = pending.get('suspension_guard')
                    except leases.LeaseError:
                        pass
                leases.write_lease(record_path, lease_path, nonce, observed_ok, failed_at,
                                   reason=reason, root=root,
                                   **({'suspension_guard': pending_guard} if pending_guard is not None else {}))
                revoked = not observed_ok
            except Exception:
                pass  # A stale or missing lease independently expires in gate.
            # Native window restoration never renews here. A browser renewal
            # above came only from the ordinary, fresh verifier's own result.
            if recovery is not None and revoked:
                recovery.try_after_revocation(str(e))
        except Exception:
            try:
                leases.write_lease(record_path, lease_path, nonce, False, time.time(),
                                   reason='environment_check_unavailable', root=root)
            except Exception:
                pass
        time.sleep(.2)


def active_monitor(kind, target, *, root=ROOT, verification_mode=None):
    try:
        key = leases.key_for(kind, target)
        record_path = Path(root) / 'environment-leases' / (key + '.registration.json')
        record = leases.read_json(record_path, root)
        if record.get('verification_mode')!=verification_mode:
            return None
        _, lease_path = leases.paths(kind, target, record['nonce'], root)
        value = leases.read_json(lease_path, root)
        now = time.time()
        if verification_mode is not None:
            leases.LeaseRegistry(root)._native_browser_policy_record(record,value)
        if kind == 'native':
            current_source = 'native-helper-sha256:' + hashlib.sha256(helper_path(root).read_bytes()).hexdigest()
            if record.get('source') != current_source:
                return None
            native_rtc_policy_module(root).verify(root, target, record['nonce'], leases, now=now)
        if (record.get('schema') == 1 and record.get('kind') == kind
                and leases.same_identity(target, record['target']) and leases.alive(target)
                and leases.alive(record['monitor']) and value.get('schema') == 1
                and value.get('nonce') == record['nonce'] and value.get('ok') is True
                and type(value.get('checked_at')) in (int, float)
                and type(value.get('written_at')) in (int, float)
                and 0 <= now - value['checked_at'] <= leases.TTL
                and 0 <= now - value['written_at'] <= leases.TTL):
            return {'kind': kind, 'monitor_pid': record['monitor']['pid'],
                    'registration': str(record_path), 'nonce': record['nonce'],
                    'lease_seconds': leases.TTL, 'reused': True}
    except Exception:
        pass
    return None


def _ps_literal(value):
    """PowerShell single-quoted data, never interpolated command syntax."""
    return "'" + str(value).replace("'", "''") + "'"


def _broker_json(script):
    shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    if not shell.is_absolute() or not shell.is_file():
        raise leases.LeaseError('monitor_broker_shell_unavailable')
    prefix = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); "
    try:
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', prefix + script],
                                capture_output=True, text=True, encoding='utf-8-sig', errors='strict',
                                timeout=15, creationflags=CREATE_NO_WINDOW)
        if result.returncode or len(result.stdout) > 32768:
            raise ValueError('broker_failed')
        return json.loads(result.stdout)
    except Exception:
        raise leases.LeaseError('monitor_broker_unavailable') from None


def _in_job(expected):
    """Read-only job membership, with creation identity before and after."""
    if not leases.same_identity(expected, leases.identity(expected['pid'])):
        raise leases.LeaseError('monitor_broker_identity_changed')
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.IsProcessInJob.argtypes = [W.HANDLE, W.HANDLE, C.POINTER(W.BOOL)]
    kernel.IsProcessInJob.restype = W.BOOL
    kernel.CloseHandle.argtypes = [W.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, expected['pid'])
    if not handle:
        raise leases.LeaseError('monitor_job_query_unavailable')
    try:
        value = W.BOOL()
        if not kernel.IsProcessInJob(handle, None, C.byref(value)):
            raise leases.LeaseError('monitor_job_query_unavailable')
        result = bool(value.value)
    finally:
        kernel.CloseHandle(handle)
    if not leases.same_identity(expected, leases.identity(expected['pid'])):
        raise leases.LeaseError('monitor_broker_identity_changed')
    return result


def _start_brokered_monitor(pythonw, root, config_path):
    """Create only our fixed checker via WMI, independent of the caller's job.

    No elevation, credentials, arbitrary command input, or Popen fallback.
    WMI success alone is not readiness: image, PID/creation, exact command/config,
    lack of inherited job, and a fresh lease are independently required.
    """
    root = Path(root)
    runtime = leases.read_json(root / 'environment-runtime.json', root)
    configured = runtime.get('python_executable')
    if (type(configured) is not str or not Path(configured).is_absolute()
            or Path(configured).name.casefold() != 'python.exe'):
        raise leases.LeaseError('monitor_runtime_invalid')
    runtime_python = Path(configured)
    runtime_directory = runtime_python.parent
    # The configured Python runtime intentionally lives outside the guard root.
    # Bind to its exact physical directory, not physical()'s guard-root default.
    runtime_python = leases.physical(runtime_python, runtime_directory)
    expected_pythonw = leases.physical(runtime_directory / 'pythonw.exe', runtime_directory)
    if (not runtime_python.is_file() or not expected_pythonw.is_file()
            or not Path(pythonw).is_absolute()
            or os.path.normcase(str(Path(pythonw))) != os.path.normcase(str(expected_pythonw))):
        raise leases.LeaseError('monitor_runtime_invalid')
    pythonw = expected_pythonw
    script = leases.physical(root / 'environment_watchdog.py', root)
    config_path = leases.physical(config_path, root)
    command = subprocess.list2cmdline([str(pythonw), '-B', str(script), '--config', str(config_path)])
    launch = ("$taskStartup=New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ShowWindow=[uint16]0}; "
              "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=" +
              _ps_literal(command) + ";CurrentDirectory=" + _ps_literal(root) +
              ";ProcessStartupInformation=$taskStartup} | Select-Object ReturnValue,ProcessId | ConvertTo-Json -Compress")
    value = _broker_json(launch)
    if (type(value) is not dict or type(value.get('ReturnValue')) is not int
            or value['ReturnValue'] != 0 or type(value.get('ProcessId')) is not int
            or not 0 < value['ProcessId'] < 0xFFFFFFFF):
        raise leases.LeaseError('monitor_broker_create_failed')
    pid = value['ProcessId']
    created = leases.identity(pid)
    if (not created or os.path.normcase(created['image']) != os.path.normcase(str(pythonw))):
        raise leases.LeaseError('monitor_broker_identity_changed')
    # Do not return or log any command line. WMI filters to this exact owned
    # image and expected command first, then emits only PID + image metadata.
    verify = ("$taskFound=@(Get-CimInstance Win32_Process -Filter 'ProcessId=" + str(pid) +
              "' | Where-Object {$_.ExecutablePath -ieq " + _ps_literal(pythonw) +
              " -and $_.CommandLine -ceq " + _ps_literal(command) +
              "} | Select-Object ProcessId,ExecutablePath); ConvertTo-Json -InputObject $taskFound -Compress")
    rows = _broker_json(verify)
    if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
            or type(rows[0].get('ProcessId')) is not int or rows[0]['ProcessId'] != pid
            or os.path.normcase(rows[0].get('ExecutablePath', '')) != os.path.normcase(str(pythonw))
            or not leases.same_identity(created, leases.identity(pid))):
        raise leases.LeaseError('monitor_broker_command_unverified')
    if _in_job(created) is not False:
        raise leases.LeaseError('monitor_broker_still_in_job')
    return created


def start_monitor(kind, target, *, nonce=None, controller=None, status_path=None, root=ROOT,verification_mode=None):
    root = Path(root)
    nonce = nonce or uuid.uuid4().hex
    record_path, lease_path = leases.paths(kind, target, nonce, root)
    base = root / 'environment-leases'
    base.mkdir(exist_ok=True)
    leases.physical(base, root)
    config_path = base / ('monitor-' + nonce + '.config.json')
    value = {'schema': 1, 'kind': kind, 'target': target, 'nonce': nonce}
    if kind == 'browser':
        value.update(controller=controller, status_path=str(status_path))
    if verification_mode is not None:
        if kind!='browser' or verification_mode!=leases.NATIVE_BROWSER_MODE:
            raise leases.LeaseError('native_browser_mode_invalid')
        value['verification_mode']=verification_mode
    leases.atomic_json(config_path, value)
    runtime = leases.read_json(root / 'environment-runtime.json', root)
    pythonw = Path(runtime['python_executable']).with_name('pythonw.exe')
    created_monitor = _start_brokered_monitor(pythonw, root, config_path)
    deadline = time.time() + 20
    while time.time() < deadline:
        if not leases.alive(created_monitor):
            raise leases.LeaseError('environment_monitor_exited')
        try:
            record = leases.read_json(record_path, root)
            lease = leases.read_json(lease_path, root)
            if (record.get('schema') == 1 and record.get('kind') == kind
                    and record.get('verification_mode')==verification_mode
                    and leases.same_identity(record.get('target', {}), target)
                    and record.get('nonce') == nonce and lease.get('schema') == 1
                    and (verification_mode is None or lease.get('reason')==leases.NATIVE_BROWSER_REASON)
                    and lease.get('nonce') == nonce and lease.get('ok') is True
                    and leases.same_identity(created_monitor, record.get('monitor'))
                    and leases.alive(created_monitor)
                    and type(lease.get('checked_at')) in (int, float)
                    and type(lease.get('written_at')) in (int, float)
                    and 0 <= time.time() - lease['checked_at'] <= leases.TTL
                    and 0 <= time.time() - lease['written_at'] <= leases.TTL):
                return {'kind': kind, 'monitor_pid': created_monitor['pid'], 'registration': str(record_path),
                        'nonce': nonce, 'lease_seconds': leases.TTL,
                        'launch_method': 'wmi_create_verified', 'monitor_in_job': False}
        except Exception:
            pass
        time.sleep(.1)
    raise leases.LeaseError('environment_monitor_not_ready')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    run_monitor(leases.physical(args.config))


if __name__ == '__main__':
    main()
