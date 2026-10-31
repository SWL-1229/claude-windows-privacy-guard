"""Candidate only: bounded observations for launch errors, never authority.

No process termination, network mutation, profile reads, arbitrary strings,
account data, URLs, argv or environment values are accepted into a snapshot.
"""
import math
import time
from pathlib import Path

STAGES = frozenset((
    'preflight', 'verify_dedicated_exit', 'acquire_hold', 'spawn_controller',
    'wait_runtime', 'register_monitor', 'release_hold', 'verify_gate',
    'activate', 'wait_activation', 'rollback', 'unknown'))
CODES = frozenset((
    'environment_controller_exited_before_ready', 'environment_child_not_confirmed_running',
    'environment_metadata_not_verified', 'environment_ready_timeout',
    'environment_monitor_not_ready', 'protected_gate_not_verified',
    'environment_controller_exited_during_activation', 'environment_child_exited_during_activation',
    'environment_changed_during_activation', 'environment_activation_timeout',
    'environment_launch_failed', 'exit_verification_unavailable', 'exit_outside_allowlist',
    'preexisting_network_hold_preserved', 'network_hold_changed_before_activation',
    'existing_environment_requires_restart', 'existing_page_health_not_verified',
    'existing_navigation_waiting_for_runtime', 'ingress_follower_not_ready',
    'native_environment_blocks_gateway', 'browser_environment_blocks_gateway',
    'environment_registry_unavailable', 'browser_navigation_not_verified',
    'browser_environment_not_verified', 'browser_controller_not_alive',
    'browser_environment_check_expired', 'browser_navigation_check_expired',
    'browser_navigation_phase_changed', 'browser_monitor_identity_unavailable',
    'browser_controller_identity_invalid', 'environment_monitor_exited',
    'unclassified_launch_failure'))
REASONS = frozenset((
    'lease_content_invalid', 'lease_expired_or_clock_invalid', 'registration_missing',
    'target_identity_invalid', 'monitor_identity_invalid', 'lease_registry_unavailable',
    'environment_registry_unavailable', 'registration_directory_missing',
    'process_creation_snapshot_invalid', 'lease_registration_invalid', 'unknown_failure'))
COUNTS = frozenset((
    'attached', 'covered_pages', 'covered_iframes', 'metadata_matches',
    'metadata_mismatches', 'workers_unverified', 'unprotected_targets',
    'unknown_target_types', 'early_unpaused_targets', 'command_errors',
    'environment_checks', 'environment_check_failures', 'environment_pending_checks',
    'navigation_windows_started', 'navigation_proofs', 'navigation_invalidations',
    'navigation_deadline_expirations'))
STATUSES = frozenset((
    'starting', 'partial', 'monitoring', 'environment_failed', 'stopping',
    'stopped', 'child_exited', 'child_shutdown_not_confirmed'))


def _counter(value):
    return value if type(value) is int and 0 <= value <= 1_000_000_000 else None


def _pid(value):
    return value if type(value) is int and 0 < value < 0xffffffff else None


def _enum(value, allowed, fallback):
    return value if type(value) is str and value in allowed else fallback


def _blocker(value):
    if type(value) is not dict:
        return None
    return {
        'reason': _enum(value.get('reason'), REASONS, 'unknown_failure'),
        'kind': _enum(value.get('kind'), ('native', 'browser'), None),
        'target_pid': _pid(value.get('target_pid')),
    }


def probe_blocker(registry):
    """Fresh read-only registry check; result is a hint, never a grant/token.

    The production guard remains the admission authority. This helper must not
    retire a live native process because it has no visible windows, nor remove
    registrations or lease files to allow a different client through.
    """
    try:
        if registry.permitted() is True:
            return None
        return _blocker(registry.last_failure) or {
            'reason': 'environment_registry_unavailable', 'kind': None, 'target_pid': None}
    except Exception:
        return {'reason': 'environment_registry_unavailable', 'kind': None, 'target_pid': None}


def snapshot(stage, code, *, report=None, blocker=None, hold_retained=False,
             controller_pid=None, now=None):
    stamp = time.time() if now is None else now
    if type(stamp) not in (float, int) or not math.isfinite(stamp) or stamp < 0:
        raise ValueError('diagnostic_clock_invalid')
    value = {'schema': 1, 'at_unix': stamp, 'diagnostic_only': True,
             'stage': _enum(stage, STAGES, 'unknown'),
             'code': _enum(code, CODES, 'unclassified_launch_failure'),
             'hold_retained': hold_retained is True, 'controller_pid': _pid(controller_pid),
             'gateway_blocker': _blocker(blocker)}
    if type(report) is dict:
        counts = report.get('counts')
        value['controller'] = {
            'status': _enum(report.get('status'), STATUSES, 'unknown'),
            'activation_attempted': report.get('activation_attempted') is True,
            'activation_complete': report.get('activation_complete') is True,
            'environment_check_ok': report.get('environment_check_ok') is True,
            'environment_check_pending': report.get('environment_check_pending') is True,
            'counts': {key: _counter(counts.get(key)) for key in sorted(COUNTS)
                       if type(counts) is dict and key in counts},
        }
    return value


def write_snapshot(root, value, leases):
    """Closed fixed destination, secure existing-directory writer; best effort.

    Failure must not alter rollback or the user's original error. The caller
    supplies its own physical leases module, never an imported report path.
    """
    try:
        root = Path(root)
        runs = leases.physical(root / 'privacy-qa' / 'runs', root)
        destination = leases.physical(runs / 'browser-launch-last-failure.json', root,
                                      missing=True)
        leases.atomic_json(destination, value)
        return True
    except Exception:
        return False
