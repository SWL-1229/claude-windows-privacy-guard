"""Local, fail-closed HTTP CONNECT gate for the installed Claude Desktop app.

No TLS interception. Only a dedicated pinned SOCKS route is used. This file does
not query or change the user's selectable system Clash routing policy.
"""
import asyncio
import concurrent.futures
import ctypes
import fnmatch
import hashlib
import importlib.util
import ipaddress
import math
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
LISTEN = ('127.0.0.1', 17894)
NORMAL_LISTEN = ('127.0.0.1', 17893)
CORE_PROXY = ('127.0.0.1', 17895)
sys.path.insert(0, str(ROOT))
from deployment_allowlist import ALLOWED
connections = set()
# Writers with an issued permission, including upstream connection attempts.
granted_connections = set()
normal_connections = set()
PROTECTED_DOMAINS = frozenset(['claude.ai', 'claude.com', 'anthropic.com',
                              'claude.app', 'claudeusercontent.com',
                              'claudemcpcontent.com'])
check_lock = None
last_ok = 0.0
last_exit = None
core_process = None
revocation_generation = 0
# Fresh network measurements on this installation were about 1.9-2.9 seconds.
# A four-second lease is deliberately aggressive; expiry fails closed.
EXIT_CACHE_SECONDS = 0.25
EXIT_LEASE_SECONDS = 4.0
# A no-result gap never grants permission. Keep an application's TCP transport
# for a bounded period while forwarding zero bytes; actual failures still
# revoke the generation and abort every protected transport immediately.
EXIT_NORESULT_PAUSE_SECONDS = 45.0
exit_noresult_pause = None
exit_noresult_pause_counts = {'started': 0, 'resumed': 0}
LOCAL_WATCHDOG_SECONDS = 0.05
ACTIVE_PROBE_GAP_SECONDS = 0.2
IDLE_PROBE_GAP_SECONDS = 3.0
MIN_PROBE_START_SECONDS = 1.0
last_probe_started = 0.0
pending_probe = None
MAX_EXIT_PROBES = 2
FIXED_EXIT_SOURCES = ('cloudflare_trace', 'ipify_json')
FIXED_PROBE_BUDGET_SECONDS = 3.5
_probe_endpoint_sequence = 0
_probe_endpoint_lock = threading.Lock()
fixed_source_diagnostics = {source:{'started':0,'succeeded':0,'transport_no_result':0,'hard_failed':0} for source in FIXED_EXIT_SOURCES}
EXIT_PROBE_WAIT_SECONDS = 15.0
_probe_manager = None
_probe_start_lock = threading.Lock()
watchdog_blocked = False
_environment_registry = None
_environment_json_writer = None
_environment_enforcement_seen = False
_environment_last_permitted = False
_environment_last_failure = None
_environment_failure_events = []
_guard_failure_events = []
_scope_route_events = []
SCOPE_PAUSE_SECONDS = 4.0
INDEPENDENT_SCOPE_PAUSE_SECONDS = 30.0
scope_pause_started = None
scope_pause_signature = None
scope_pause_generation = None
scope_pause_deadline = None
scope_pause_phase = None
scope_pause_recovery_after = None
scope_pause_counts = {'started': 0, 'resumed': 0}
environment_transmission_state = 'denied'
transmission_diagnostic = {}
watchdog_first_revocation = None
LOADED_SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


# Native policy observation freshness is separate from the four-second IP grant.
NATIVE_SNAPSHOT_MAX_SECONDS = .5
_native_policy_observer = None
native_snapshot_diagnostic = {'mode':'not_started','reason':'not_started'}
watchdog_last_revocation = None
watchdog_first_unplanned_revocation = None
watchdog_scheduling = {'samples':0,'last_lag_ms':0.,'max_lag_ms':0.}
probe_scheduling = {'completed':0,'last_duration_ms':None,'max_duration_ms':0.,'last_collection_lag_ms':None,'max_collection_lag_ms':0.}


def _snapshot_local_policy():
    # Existing small local policies only, no process or registration scan.
    if (ROOT/'hold.block').exists():raise RuntimeError('Manual offline hold')
    file=ROOT/'environment-enforcement.json'
    if file.resolve(strict=True)!=file.absolute() or json.loads(file.read_text(encoding='utf-8-sig'))!={'schema':1,'enabled':True}:
        raise RuntimeError('Environment enforcement policy invalid')
    return tuple(sorted(configured_allowlist()))


class NativePolicyObserver:
    """Single serialized control worker, separate from peer-attribution registry."""
    def __init__(self,*,registry_factory=None,monotonic=time.monotonic,wall=time.time,policy_reader=None,generation_reader=None):
        self.registry_factory=registry_factory or self._registry;self.monotonic=monotonic;self.wall=wall
        self.policy_reader=policy_reader or _snapshot_local_policy;self.generation_reader=generation_reader or (lambda:revocation_generation)
        self.stop_event=threading.Event();self.lock=threading.Lock();self.thread=None;self.registry=None
        self.observation={'mode':'pending','state':'denied','reason':'native_snapshot_pending'}
        self.stats={'completed':0,'last_duration_ms':None,'max_duration_ms':0.,'last_reason':'native_snapshot_pending'}
    @staticmethod
    def _registry():
        global _environment_json_writer
        source=ROOT/'environment_lease.py'
        if source.resolve(strict=True)!=source.absolute():raise RuntimeError('Environment lease module path changed')
        spec=importlib.util.spec_from_file_location('claude_native_snapshot_lease',source)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        _environment_json_writer=module.atomic_json
        return module.LeaseRegistry(ROOT)
    def start(self):
        if self.thread is not None:raise RuntimeError('Snapshot worker already started')
        self.thread=threading.Thread(target=self.run,name='native-policy-observer',daemon=True);self.thread.start()
    def scan_once(self):
        began=self.monotonic();wall_began=self.wall();generation=self.generation_reader()
        value={'mode':'native','state':'denied','signature':None,'reason':'native_snapshot_check_failed','generation':generation,'started_mono':began,'started_wall':wall_began}
        try:
            before=self.policy_reader()
            if self.registry is None:self.registry=self.registry_factory()
            result=self.registry.transmission_state()
            records=[item[0] for item in self.registry.records.values()]
            value['registration_count']=len(records)
            opted=[record for record in records if record.get('verification_mode') is not None]
            native_only=bool(records) and len(opted)==len(records) and all(r.get('kind')=='browser' and r.get('verification_mode')=='native_process_policy_v1' for r in records)
            known_scope=all(r.get('kind') in ('browser','native') and (r.get('verification_mode') is None or r.get('kind')=='browser' and r.get('verification_mode')=='native_process_policy_v1') for r in records)
            snapshot_environment_scope=bool(records) and all(
                (r.get('kind')=='native' and r.get('verification_mode') is None)
                or (r.get('kind')=='browser' and r.get('verification_mode')=='native_process_policy_v1')
                for r in records)
            desktop_only=bool(records) and all(r.get('kind')=='native' and r.get('verification_mode') is None for r in records)
            value['scope_kind']=('browser-only' if native_only else 'native-only' if desktop_only
                                 else 'mixed' if snapshot_environment_scope else 'unsupported')
            after=self.policy_reader();finished=self.monotonic();wall_finished=self.wall()
            if before!=after:raise RuntimeError('Local policy changed during observation')
            if generation!=self.generation_reader():value['reason']='native_snapshot_generation_changed'
            elif not 0<=finished-began or not wall_began<=wall_finished:value['reason']='native_snapshot_check_clock_invalid'
            elif (snapshot_environment_scope and not native_only
                    and result.get('state')=='permitted'
                    and result.get('verified_environment_only') is True
                    and type(result.get('environment_valid_until')) in (int,float)
                    and math.isfinite(result['environment_valid_until'])
                    and type(result.get('environment_observed_not_before')) in (int,float)
                    and math.isfinite(result['environment_observed_not_before'])
                    and result['environment_observed_not_before']<=wall_finished<result['environment_valid_until']
                    and 0<result['environment_valid_until']-wall_finished<=EXIT_LEASE_SECONDS):
                value.update(mode='environment',state='permitted',reason='environment_snapshot_verified',
                    signature=result.get('signature'),policy=after,
                    valid_until_wall=result['environment_valid_until'],
                    valid_until_mono=finished+(result['environment_valid_until']-wall_finished),
                    observed_not_before=result['environment_observed_not_before'])
            elif snapshot_environment_scope and not native_only and result.get('state')=='permitted':
                value['reason']='environment_snapshot_evidence_invalid'
            elif known_scope and not native_only and result.get('state') in ('permitted','suspended'):
                # A complete known legacy/empty observation alone hands off.
                value.update(mode='legacy',reason='explicit_legacy_scope',policy=after)
            elif (native_only and result.get('state')=='permitted' and result.get('native_process_policy_only') is True
                    and type(result.get('policy_valid_until')) in (int,float) and math.isfinite(result['policy_valid_until'])
                    and type(result.get('policy_observed_not_before')) in (int,float) and math.isfinite(result['policy_observed_not_before'])
                    and result['policy_observed_not_before']<=wall_finished<result['policy_valid_until']
                    and 0<result['policy_valid_until']-wall_finished<=EXIT_LEASE_SECONDS):
                value.update(state='permitted',reason='native_snapshot_verified',signature=result.get('signature'),policy=after,
                    valid_until_wall=result['policy_valid_until'],valid_until_mono=finished+(result['policy_valid_until']-wall_finished),
                    observed_not_before=result['policy_observed_not_before'])
            else:value['reason']='native_snapshot_policy_denied'
        except Exception:pass  # Unknown, mixed, invalid and failed never hand off.
        finished=self.monotonic();wall_finished=self.wall();duration=finished-began
        value.update(completed_mono=finished,completed_wall=wall_finished,duration_seconds=duration)
        if not 0<=duration or not wall_began<=wall_finished:
            value.update(mode='native',state='denied',reason='native_snapshot_check_clock_invalid')
        elif duration>NATIVE_SNAPSHOT_MAX_SECONDS:
            # A complete, valid original receipt is not a fresh data-plane
            # observation if this scan took too long. It may only confirm a
            # prior exact scope while transmission remains paused.
            eligible=value.get('state')=='permitted' and value.get('mode') in ('native','environment')
            value.update(state='denied',reason='native_snapshot_check_slow',slow_complete_receipt=eligible)
        with self.lock:
            self.observation=value;self.stats['completed']+=1;self.stats['last_duration_ms']=round(duration*1000,3)
            self.stats['max_duration_ms']=round(max(self.stats['max_duration_ms'],duration*1000),3);self.stats['last_reason']=value['reason']
        return value
    def run(self):
        while not self.stop_event.is_set():
            began=self.monotonic();self.scan_once();self.stop_event.wait(max(0,LOCAL_WATCHDOG_SECONDS-(self.monotonic()-began)))
    def read(self):
        with self.lock:return dict(self.observation),dict(self.stats)
    def close(self):
        self.stop_event.set()
        if self.thread is not None:self.thread.join(2)


class NativeSnapshotContinuity:
    """No permission: a fixed original environment deadline for zero-byte waits."""
    def __init__(self):
        self.receipt=None;self.pause=None;self.counts={'started':0,'resumed':0,'hard_failed':0}
    def clear(self):
        self.receipt=None;self.pause=None
    def deny(self,reason):
        if self.pause is not None:
            if not self.pause['hard_failed']:self.counts['hard_failed']+=1
            self.pause['hard_failed']=True
        else:self.receipt=None
        return {'state':'denied','reason':reason,'signature':None}
    @staticmethod
    def receipt_value(value,now,wall,generation,policy):
        kind=value.get('scope_kind');mode=value.get('mode');signature=value.get('signature')
        numbers=[value.get(k) for k in ('valid_until_wall','valid_until_mono','observed_not_before')]
        if (not ((kind=='browser-only' and mode=='native') or (kind in ('native-only','mixed') and mode=='environment'))
                or type(value.get('registration_count')) is not int or value['registration_count']<=0
                or type(signature) is not str or len(signature)!=64 or any(c not in 'abcdef0123456789' for c in signature)
                or value.get('generation')!=generation or value.get('policy')!=policy
                or any(type(v) not in (int,float) or not math.isfinite(v) for v in numbers)
                or not numbers[2]<=wall<numbers[0]<=wall+EXIT_LEASE_SECONDS
                or not now<numbers[1]<=now+EXIT_LEASE_SECONDS):return None
        return {'kind':kind,'signature':signature,'generation':generation,'policy':policy,
                'valid_until_wall':numbers[0],'valid_until_mono':numbers[1]}
    def observe(self,value,*,now,wall,generation,policy):
        age=now-value.get('completed_mono',float('nan'));duration=value.get('duration_seconds')
        if (type(age) not in (int,float) or not math.isfinite(age) or age<0
                or type(duration) not in (int,float) or not math.isfinite(duration) or duration<0
                or type(value.get('completed_wall')) not in (int,float) or not math.isfinite(value['completed_wall']) or wall<value['completed_wall']
                or value.get('generation')!=generation or value.get('policy')!=policy):
            return self.deny('native_snapshot_identity_clock_or_policy_invalid')
        receipt=self.receipt_value(value,now,wall,generation,policy)
        fresh=(age<=NATIVE_SNAPSHOT_MAX_SECONDS and duration<=NATIVE_SNAPSHOT_MAX_SECONDS
               and value.get('state')=='permitted' and receipt is not None)
        if self.pause is not None:
            anchor=self.pause
            if (anchor['hard_failed'] or anchor['generation']!=generation or anchor['policy']!=policy
                    or now>=anchor['valid_until_mono'] or wall>=anchor['valid_until_wall']):
                return self.deny('native_snapshot_pause_original_deadline_or_identity_invalid')
            if receipt is not None and (receipt['signature']!=anchor['signature'] or receipt['kind']!=anchor['kind']):
                return self.deny('native_snapshot_pause_scope_changed')
        if fresh:
            if self.pause is not None:
                self.counts['resumed']+=1;self.pause=None
            self.receipt=receipt
            return {'state':'permitted','reason':'environment_snapshot_verified' if value['mode']=='environment' else 'native_snapshot_verified','signature':receipt['signature']}
        unavailable=((age>NATIVE_SNAPSHOT_MAX_SECONDS and duration<=NATIVE_SNAPSHOT_MAX_SECONDS and value.get('state')=='permitted')
                     or (value.get('state')=='denied' and value.get('reason')=='native_snapshot_check_slow'
                         and value.get('slow_complete_receipt') is True and duration>NATIVE_SNAPSHOT_MAX_SECONDS))
        old=self.receipt
        if (not unavailable or receipt is None or old is None or old['generation']!=generation
                or old['policy']!=policy or old['signature']!=receipt['signature'] or old['kind']!=receipt['kind']
                or now>=old['valid_until_mono'] or wall>=old['valid_until_wall']):
            return self.deny(value.get('reason') if value.get('state')=='denied' else 'native_snapshot_original_evidence_expired')
        if self.pause is None:
            self.pause=dict(old,started_mono=now,hard_failed=False);self.counts['started']+=1
        return {'state':'suspended','reason':'native_snapshot_temporarily_unavailable','signature':old['signature']}
    def diagnostic(self,now):
        return {'counts':dict(self.counts),'active':self.pause is not None,
                'original_seconds_remaining':max(0.,self.pause['valid_until_mono']-now) if self.pause else None,
                'forwards_application_bytes':False}


_native_snapshot_continuity=NativeSnapshotContinuity()
_native_snapshot_continuity_owner=None


def native_admission_observation():
    """500ms observation freshness; an absent refresh only pauses existing bytes."""
    global native_snapshot_diagnostic,_native_snapshot_continuity_owner
    observer=_native_policy_observer
    if observer is None:return None
    if _native_snapshot_continuity_owner is not observer:
        _native_snapshot_continuity.clear();_native_snapshot_continuity_owner=observer
    value,stats=observer.read();now=time.monotonic();wall=time.time()
    age=now-value['completed_mono'] if type(value.get('completed_mono')) in (int,float) else None
    try:
        policy=_snapshot_local_policy()
        fresh_legacy=(value.get('mode')=='legacy' and value.get('generation')==revocation_generation
            and type(age) in (int,float) and 0<=age<=NATIVE_SNAPSHOT_MAX_SECONDS
            and type(value.get('duration_seconds')) in (int,float) and 0<=value['duration_seconds']<=NATIVE_SNAPSHOT_MAX_SECONDS
            and type(value.get('completed_wall')) in (int,float) and wall>=value['completed_wall'] and policy==value.get('policy'))
        if fresh_legacy:
            if _native_snapshot_continuity.pause is None:
                _native_snapshot_continuity.clear()
                native_snapshot_diagnostic={'mode':'legacy','reason':'explicit_legacy_scope','registration_count':value.get('registration_count'),'scope_kind':value.get('scope_kind'),'age_ms':round(age*1000,3),**stats};return None
            result=_native_snapshot_continuity.deny('native_snapshot_pause_scope_changed')
        else:result=_native_snapshot_continuity.observe(value,now=now,wall=wall,generation=revocation_generation,policy=policy)
        if result['state']=='suspended' and 'exit' not in _native_snapshot_continuity.pause:
            _native_snapshot_continuity.pause.update(exit=last_exit,exit_checked_mono=last_ok)
    except Exception:
        result=_native_snapshot_continuity.deny('native_snapshot_local_policy_invalid')
    native_snapshot_diagnostic={'mode':value.get('mode'),'reason':result['reason'],'registration_count':value.get('registration_count'),
        'scope_kind':value.get('scope_kind'),'age_ms':round(age*1000,3) if age is not None else None,
        'zero_byte_continuity':_native_snapshot_continuity.diagnostic(now),**stats}
    return result


def snapshot_pause_scope(generation):
    """A bounded same-scope wait descriptor, never a fresh environment grant."""
    observation=native_admission_observation();anchor=_native_snapshot_continuity.pause
    if (not isinstance(observation,dict) or observation.get('state')!='suspended'
            or observation.get('reason')!='native_snapshot_temporarily_unavailable' or anchor is None
            or generation!=revocation_generation or anchor['generation']!=generation):return None
    if (last_exit is not None and last_exit not in anchor['policy']
            or anchor.get('exit') is not None and last_exit!=anchor['exit']
            or type(last_ok) not in (int,float) or not math.isfinite(last_ok)
            or last_ok<0 or time.monotonic()<last_ok):
        _native_snapshot_continuity.deny('native_snapshot_pause_exit_changed')
        return None
    if exit_noresult_pause is not None:
        exit_anchor=exit_noresult_pause
        if (exit_anchor['generation']!=generation or exit_anchor['exit']!=last_exit
                or exit_anchor['original_checked_mono']!=last_ok or exit_anchor['scope_kind']!=anchor['kind']
                or exit_anchor['scope_signature']!=anchor['signature'] or exit_anchor['allowlist']!=anchor['policy']
                or time.monotonic()>=exit_anchor['deadline_mono']):
            _native_snapshot_continuity.deny('native_snapshot_combined_exit_anchor_changed')
            return None
    return {'kind':anchor['kind'],'signature':anchor['signature']}


def environment_registry():
    global _environment_registry, _environment_enforcement_seen, _environment_json_writer
    policy = ROOT / 'environment-enforcement.json'
    _environment_enforcement_seen = True
    if policy.resolve(strict=True) != policy.absolute():
        raise RuntimeError('Environment enforcement path changed')
    value = json.loads(policy.read_text(encoding='utf-8-sig'))
    if value != {'schema': 1, 'enabled': True}:
        raise RuntimeError('Environment enforcement policy invalid')
    if _environment_registry is None:
        source = ROOT / 'environment_lease.py'
        if source.resolve(strict=True) != source.absolute():
            raise RuntimeError('Environment lease module path changed')
        spec = importlib.util.spec_from_file_location('claude_gate_environment_lease', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _environment_registry = module.LeaseRegistry(ROOT)
        _environment_json_writer = module.atomic_json
    return _environment_registry


def environment_permitted():
    global _environment_last_permitted, _environment_last_failure
    fast=native_admission_observation()
    if fast is not None:
        _environment_last_permitted=fast['state']=='permitted'
        if not _environment_last_permitted:_environment_last_failure={'at':time.time(),'detail':{'reason':fast['reason']}}
        return _environment_last_permitted
    try:
        registry = environment_registry()
        _environment_last_permitted = registry is not None and registry.permitted()
        if not _environment_last_permitted:
            _environment_last_failure = {
                'at': time.time(),
                'detail': getattr(registry, 'last_failure', None) or {'reason': 'environment_permission_denied'}}
    except Exception:
        _environment_last_permitted = False
        _environment_last_failure = {'at': time.time(), 'detail': {'reason': 'environment_registry_unavailable'}}
    if not _environment_last_permitted:
        entry = _environment_last_failure
        detail = entry['detail']
        same = bool(_environment_failure_events and all(
            _environment_failure_events[-1]['detail'].get(key) == detail.get(key)
            for key in ('reason', 'kind', 'target_pid')))
        if same:
            _environment_failure_events[-1]['last_at'] = entry['at']
            _environment_failure_events[-1]['count'] += 1
        else:
            _environment_failure_events.append(dict(entry, last_at=entry['at'], count=1))
            del _environment_failure_events[:-16]
    return _environment_last_permitted


def observe_transmission_diagnostic(observation):
    global transmission_diagnostic
    reasons = {'registry_scan_failed', 'registration_or_identity_invalid', 'lease_content_invalid',
        'browser_false_or_controller_invalid', 'false_lease_not_suspendable', 'true_lease_has_suspension_data',
        'lease_heartbeat_or_runtime_expired', 'suspension_deadline_expired', 'registry_observation_failed',
        'browser_suspension_bootstrap_invalid', 'browser_suspension_proof_invalid', 'browser_suspension_proof_expired',
        'browser_suspension_source_invalid', 'browser_suspension_source_expired', 'browser_suspension_recovery_not_new',
        'browser_suspension_phase_changed', 'zero_byte_suspension', 'legacy_scope_transition',
        'verified_environment_leases', 'no_active_registered_environment',
        'native_browser_registration_invalid','native_browser_lease_invalid','native_browser_mode_missing',
        'native_browser_source_invalid','native_browser_startup_invalid','native_browser_source_expired_or_changed'}
    wall = time.time()
    def number(key):
        value = observation.get(key)
        return value if type(value) in (int, float) and math.isfinite(value) else None
    phase = observation.get('suspension_phase')
    previous = transmission_diagnostic
    # A rejected registry read may intentionally omit untrusted proof fields.
    # Preserve the last observed clocks for diagnostics only; admission below
    # still uses this call's registry evidence and its immutable local anchor.
    retain = observation.get('state') == 'denied' and scope_pause_started is not None
    def observed_number(field, previous_field):
        value = number(field)
        return previous.get(previous_field) if value is None and retain else value
    transmission_diagnostic = {'state': observation.get('state') if observation.get('state') in ('denied', 'suspended', 'permitted') else 'denied',
        'reason': observation.get('reason') if observation.get('reason') in reasons else 'not_reported',
        'phase': phase if type(phase) is str and len(phase) == 64 and all(c in 'abcdef0123456789' for c in phase) else previous.get('phase') if retain else None,
        'started_at': observed_number('suspension_started_at', 'started_at'),
        'deadline_at': observed_number('suspension_deadline', 'deadline_at'),
        'heartbeat_checked_at': observed_number('suspension_checked_at', 'heartbeat_checked_at'),
        'runtime_checked_at': observed_number('suspension_runtime_checked_at', 'runtime_checked_at'),
        'lease_written_at': observed_number('suspension_written_at', 'lease_written_at')}
    for name, field in (('phase_age_seconds', 'suspension_started_at'),
                        ('heartbeat_age_seconds', 'suspension_checked_at'),
                        ('runtime_age_seconds', 'suspension_runtime_checked_at'),
                        ('lease_write_age_seconds', 'suspension_written_at')):
        key = {'suspension_started_at': 'started_at', 'suspension_checked_at': 'heartbeat_checked_at',
               'suspension_runtime_checked_at': 'runtime_checked_at', 'suspension_written_at': 'lease_written_at'}[field]
        value = transmission_diagnostic[key]
        transmission_diagnostic[name] = round(wall-value, 4) if value is not None else None


def transmission_result(state, reason=None):
    global environment_transmission_state
    environment_transmission_state = state
    transmission_diagnostic['state'] = state
    if reason is not None:
        transmission_diagnostic['reason'] = reason
    return state


def transmission_state():
    """A suspended state is never an environment grant."""
    global scope_pause_started, scope_pause_signature, scope_pause_generation, scope_pause_deadline, scope_pause_phase, scope_pause_recovery_after, _environment_last_permitted, environment_transmission_state
    environment_transmission_state = 'denied'
    fast=native_admission_observation()
    if fast is not None:
        if scope_pause_started is not None:
            _environment_last_permitted=False
            return transmission_result('denied','native_snapshot_legacy_pause_not_reusable')
        _environment_last_permitted=fast['state']=='permitted'
        return transmission_result(fast['state'],fast['reason'])
    try:
        registry = environment_registry()
        observation = registry.transmission_state()
        observe_transmission_diagnostic(observation)
        state, signature = observation.get('state'), observation.get('signature')
    except Exception:
        _environment_last_permitted = False
        return transmission_result('denied', 'registry_unavailable')
    _environment_last_permitted = False
    if state == 'permitted':
        if scope_pause_started is not None:
            # Expiry wins over a coincident recovery. Existing connections may
            # only resume while their original, exact pause is still valid.
            deadline = scope_pause_deadline if scope_pause_deadline is not None else scope_pause_started + SCOPE_PAUSE_SECONDS
            if (time.monotonic() >= deadline
                    or signature != scope_pause_signature
                    or scope_pause_generation != revocation_generation):
                return transmission_result('denied', 'suspension_anchor_or_identity_invalid')
            if scope_pause_phase is not None:
                actual_runtime = observation.get('browser_runtime_verified_at')
                if (type(actual_runtime) not in (int, float) or not math.isfinite(actual_runtime)
                        or actual_runtime <= scope_pause_recovery_after
                        or not 0 <= time.time() - actual_runtime <= EXIT_LEASE_SECONDS):
                    # A fresh navigation-continuity grant is not the new,
                    # completed full-scope runtime needed to release old bytes.
                    environment_transmission_state = 'suspended'
                    return transmission_result('suspended', 'waiting_new_fullscope_runtime')
            if time.monotonic() >= deadline or scope_pause_generation != revocation_generation:
                return transmission_result('denied', 'suspension_anchor_expired')
        if scope_pause_started is not None:
            scope_pause_counts['resumed'] += 1
        scope_pause_started = scope_pause_signature = scope_pause_generation = None
        scope_pause_deadline = scope_pause_phase = scope_pause_recovery_after = None
        _environment_last_permitted = True
        environment_transmission_state = 'permitted'
        return transmission_result('permitted')
    if state != 'suspended' or not signature:
        return transmission_result('denied')
    now = time.monotonic()
    phase = observation.get('suspension_phase')
    wall_deadline, started = observation.get('suspension_deadline'), observation.get('suspension_started_at')
    if phase is not None:
        wall_now = time.time()
        if (type(phase) is not str or len(phase) != 64
                or any(c not in 'abcdef0123456789' for c in phase)
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in (wall_deadline, started))
                or not started <= wall_now < wall_deadline <= started + INDEPENDENT_SCOPE_PAUSE_SECONDS):
            return transmission_result('denied', 'suspension_proof_invalid')
    if scope_pause_started is None:
        scope_pause_counts['started'] += 1
        scope_pause_started, scope_pause_signature = now, signature
        scope_pause_generation = revocation_generation
        scope_pause_phase = phase
        scope_pause_recovery_after = started if phase is not None else None
        scope_pause_deadline = now + (min(INDEPENDENT_SCOPE_PAUSE_SECONDS, wall_deadline - time.time())
                                      if phase is not None else SCOPE_PAUSE_SECONDS)
    if (signature != scope_pause_signature or revocation_generation != scope_pause_generation
            or phase != scope_pause_phase
            or not 0 <= now - scope_pause_started
            or time.monotonic() >= scope_pause_deadline):
        return transmission_result('denied', 'suspension_anchor_or_identity_invalid')
    environment_transmission_state = 'suspended'
    return transmission_result('suspended')


def sanitized_probe_error(error, stage):
    """Fixed-enum diagnostic metadata; never retain exception text or targets.

    This records no result and does not influence failure classification,
    certificate verification, endpoint selection, grants, or lease lifetime.
    """
    kinds = (
        (ssl.SSLCertVerificationError, 'ssl_certificate_verification'),
        (ssl.SSLEOFError, 'ssl_eof'), (ssl.SSLZeroReturnError, 'ssl_closed'),
        (ssl.SSLWantReadError, 'ssl_want_read'), (ssl.SSLWantWriteError, 'ssl_want_write'),
        (ssl.SSLError, 'ssl_error'), (urllib.error.HTTPError, 'http_error'),
        (urllib.error.URLError, 'url_error'), (TimeoutError, 'timeout'),
        (http.client.RemoteDisconnected, 'remote_disconnected'),
        (ConnectionRefusedError, 'connection_refused'), (ConnectionResetError, 'connection_reset'),
        (ConnectionAbortedError, 'connection_aborted'), (BrokenPipeError, 'broken_pipe'),
        (socket.gaierror, 'dns_error'), (OSError, 'os_error'),
        (RuntimeError, 'runtime_error'))
    def kind(value):
        return next((name for cls, name in kinds if isinstance(value, cls)),
                    'text' if isinstance(value, str) else 'unknown')
    def integer(value):
        return value if type(value) is int and -(2 ** 31) <= value < 2 ** 31 else None
    inner = error.reason if isinstance(error, urllib.error.URLError) else error
    ssl_reasons = frozenset((
        'CERTIFICATE_VERIFY_FAILED', 'UNEXPECTED_EOF_WHILE_READING',
        'TLSV1_ALERT_INTERNAL_ERROR', 'SSLV3_ALERT_HANDSHAKE_FAILURE',
        'WRONG_VERSION_NUMBER', 'TLSV1_ALERT_PROTOCOL_VERSION',
        'TLSV1_ALERT_DECODE_ERROR', 'TLSV1_ALERT_UNKNOWN_CA',
        'DECRYPTION_FAILED_OR_BAD_RECORD_MAC', 'SSLV3_ALERT_BAD_RECORD_MAC',
        'UNSUPPORTED_PROTOCOL', 'TLSV1_ALERT_ACCESS_DENIED',
        'TLSV1_ALERT_INSUFFICIENT_SECURITY', 'TLSV1_ALERT_DECRYPT_ERROR',
        'SSLV3_ALERT_CERTIFICATE_EXPIRED', 'SSLV3_ALERT_CERTIFICATE_UNKNOWN',
        'TLSV1_ALERT_CERTIFICATE_REQUIRED', 'NO_SHARED_CIPHER',
        'DH_KEY_TOO_SMALL', 'EE_KEY_TOO_SMALL', 'CA_KEY_TOO_SMALL',
        'CA_MD_TOO_WEAK', 'UNEXPECTED_MESSAGE', 'TLSV1_ALERT_USER_CANCELLED'))
    ssl_reason = getattr(inner, 'reason', None) if isinstance(inner, ssl.SSLError) else None
    return {
        'stage': stage if stage in ('exit_probe_transport', 'exit_verification') else 'unknown',
        'operation': 'fixed_https_exit_probe', 'error_type': kind(error),
        'reason_type': kind(inner),
        'errno': integer(getattr(inner, 'errno', None)) if isinstance(inner, OSError) else None,
        'winerror': integer(getattr(inner, 'winerror', None)) if isinstance(inner, OSError) else None,
        'ssl_reason': ssl_reason if type(ssl_reason) is str and ssl_reason in ssl_reasons else 'unknown',
        'certificate_verify_code': integer(getattr(inner, 'verify_code', None))
            if isinstance(inner, ssl.SSLCertVerificationError) else None,
    }


def record_guard_failure(stage, error):
    # Fixed diagnostic enums and aggregate counters only. No request target,
    # header, profile, account data or arbitrary exception text is retained.
    approved = {
        'Connection permission expired', 'Connection permission was revoked',
        'Private environment lease expired or failed',
        'Probe permission was revoked while checking',
        'Exit policy changed during verification', 'Pinned upstream refused tunnel',
        'Manual offline hold', 'Local exit policy no longer permits this connection',
        'Client connection was already revoked'}
    text = str(error)
    _guard_failure_events.append({
        'at': time.time(), 'stage': stage, 'error_class': type(error).__name__,
        'reason': text if text in approved else 'operation_failed',
        'exit_lease_age': round(time.monotonic() - last_ok, 4) if last_ok > 0 else None,
        'exit_known': last_exit is not None, 'environment_permitted': _environment_last_permitted,
        'connections': len(connections), 'granted': len(granted_connections)})
    if stage in ('exit_probe_transport', 'exit_verification'):
        _guard_failure_events[-1]['probe_error'] = sanitized_probe_error(error, stage)
    del _guard_failure_events[:-24]


PEER_ATTRIBUTION_WORKERS = 4
PEER_ATTRIBUTION_CAPACITY = 64
PEER_ATTRIBUTION_SECONDS = 4.0
_private_peer_worker = None


def _private_peer_checker_factory():
    # Each physical worker owns its registry/descendant cache. No registry
    # object is shared with another worker or the data-plane event loop.
    registry = NativePolicyObserver._registry()
    def policy():
        path = ROOT / 'environment-enforcement.json'
        if path.resolve(strict=True) != path.absolute() or json.loads(path.read_text(encoding='utf-8-sig')) != {'schema':1,'enabled':True}:
            raise RuntimeError('Private peer enforcement invalid')
    def check(peer):
        policy()
        # The existing fresh registration scan, kernel TCP owner lookup and
        # exact PID birth/image/lineage checks are retained for every request.
        scoped = registry.scoped_peer(peer, NORMAL_LISTEN[1])
        policy()
        return {'scoped': scoped, 'browser_pids': sorted({r[0]['target']['pid'] for r in registry.records.values() if r[0]['kind'] == 'browser'})}
    return check


class PrivatePeerAttributor:
    """Bounded native peer checks that cannot block the forwarding loop.

    No cached ordinary result or fallback is used. A failed, over-budget,
    saturated or cancelled check rejects only that new request. The physical
    work remains bounded even when a Windows call outlives its waiter.
    """
    def __init__(self, checker_factory=None, *, workers=PEER_ATTRIBUTION_WORKERS,
                 capacity=PEER_ATTRIBUTION_CAPACITY, seconds=PEER_ATTRIBUTION_SECONDS):
        import queue
        if type(workers) is not int or not 1 <= workers <= 4 or type(capacity) is not int or not workers <= capacity <= 64:
            raise ValueError('Private peer worker bounds invalid')
        if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0 < seconds <= 4:
            raise ValueError('Private peer deadline invalid')
        self.factory=checker_factory or _private_peer_checker_factory
        self.seconds=seconds;self.queue=queue.Queue(maxsize=capacity)
        self.slots=threading.BoundedSemaphore(capacity);self.closed=threading.Event()
        self.metrics_lock=threading.Lock()
        self.metrics={'submitted':0,'completed':0,'expired':0,'saturated':0,'failed':0,'max_check_ms':0.,'max_queue_ms':0.}
        self.threads=[threading.Thread(target=self._run,name='private-peer-attribution-'+str(i),daemon=True) for i in range(workers)]
        for thread in self.threads:thread.start()
    def _metric(self,name,amount=1):
        with self.metrics_lock:self.metrics[name]+=amount
    def diagnostics(self):
        with self.metrics_lock:return dict(self.metrics,workers=len(self.threads),capacity=self.queue.maxsize,deadline_seconds=self.seconds)
    @staticmethod
    def _deliver(loop, future, value, error):
        def commit():
            if future.done():return
            if error is not None:future.set_exception(RuntimeError(error))
            else:future.set_result(value)
        try:loop.call_soon_threadsafe(commit)
        except RuntimeError:pass  # A closed owning loop cannot use this result.
    def _run(self):
        import queue
        checker=None
        while not self.closed.is_set() or not self.queue.empty():
            try:job=self.queue.get(timeout=.1)
            except queue.Empty:continue
            loop,future,peer,began,deadline,cancelled=job
            value=None;error=None;check_started=time.monotonic()
            try:
                if self.closed.is_set() or cancelled.is_set():raise RuntimeError('private_peer_cancelled')
                if check_started>=deadline:raise TimeoutError('private_peer_expired')
                if checker is None:checker=self.factory()
                value=checker(peer)
                finished=time.monotonic()
                if not began<=check_started<=finished<deadline or cancelled.is_set() or self.closed.is_set():
                    raise TimeoutError('private_peer_expired')
                if (type(value) is not dict or set(value)!={'scoped','browser_pids'} or type(value['scoped']) is not bool
                        or type(value['browser_pids']) is not list or len(value['browser_pids'])>128
                        or any(type(pid) is not int or pid<=0 for pid in value['browser_pids'])):
                    raise RuntimeError('private_peer_result_invalid')
                self._metric('completed')
            except TimeoutError:
                error='Private peer attribution expired';self._metric('expired')
            except Exception:
                error='Private peer attribution failed';self._metric('failed')
            finally:
                finished=time.monotonic()
                with self.metrics_lock:
                    self.metrics['max_check_ms']=max(self.metrics['max_check_ms'],(finished-check_started)*1000)
                    self.metrics['max_queue_ms']=max(self.metrics['max_queue_ms'],(check_started-began)*1000)
                self.slots.release();self.queue.task_done()
                self._deliver(loop,future,value,error)
    async def check(self,peer):
        if (self.closed.is_set() or type(peer) is not tuple or len(peer)!=2 or peer[0]!='127.0.0.1'
                or type(peer[1]) is not int or not 1<=peer[1]<=65535):
            raise RuntimeError('Private peer endpoint invalid')
        if not self.slots.acquire(blocking=False):
            self._metric('saturated');raise RuntimeError('Private peer attribution busy')
        loop=asyncio.get_running_loop();future=loop.create_future();cancelled=threading.Event()
        began=time.monotonic();deadline=began+self.seconds
        try:
            self.queue.put_nowait((loop,future,peer,began,deadline,cancelled));self._metric('submitted')
        except BaseException:
            self.slots.release();raise
        try:
            value=await asyncio.wait_for(asyncio.shield(future),self.seconds)
            if self.closed.is_set() or not began<=time.monotonic()<deadline:
                raise RuntimeError('Private peer attribution expired')
            return value
        except asyncio.TimeoutError:
            raise RuntimeError('Private peer attribution expired') from None
        finally:
            cancelled.set()
            if not future.done():future.cancel()
    def close(self):
        self.closed.set()


async def private_environment_peer_async(writer):
    global _private_peer_worker
    if _private_peer_worker is None:_private_peer_worker=PrivatePeerAttributor()
    peer=writer.get_extra_info('peername')
    try:
        value=await _private_peer_worker.check(peer)
        if writer.is_closing() or writer.get_extra_info('peername')!=peer:
            raise RuntimeError('Private peer connection ended')
        if value['browser_pids']:
            _scope_route_events.append({'at':time.time(),'source_port':peer[1],'scoped':value['scoped'],
                'registered_browser_pids':value['browser_pids']})
            del _scope_route_events[:-24]
        return value['scoped']
    except Exception:
        _scope_route_events.append({'at':time.time(),'source_port':peer[1] if peer else None,'refused_unresolved_scope':True})
        del _scope_route_events[:-24]
        raise


def private_environment_peer(writer):
    registry = environment_registry()
    peer = writer.get_extra_info('peername')
    try:
        result = bool(registry and registry.scoped_peer(peer, NORMAL_LISTEN[1]))
        if registry and any(r[0]['kind'] == 'browser' for r in registry.records.values()):
            _scope_route_events.append({'at': time.time(), 'source_port': peer[1], 'scoped': result,
                                        'registered_browser_pids': [r[0]['target']['pid'] for r in registry.records.values()
                                                                    if r[0]['kind'] == 'browser']})
            del _scope_route_events[:-24]
        return result
    except Exception:
        _scope_route_events.append({'at': time.time(), 'source_port': peer[1] if peer else None,
                                    'refused_unresolved_scope': True})
        del _scope_route_events[:-24]
        raise


def status(ok, reason, exit_ip=None):
    obj = {'allowed': bool(ok), 'reason': reason, 'exit_ip': exit_ip,
           'updated': time.time(), 'pid': os.getpid(),
           'loaded_source_sha256': LOADED_SOURCE_SHA256,
           'environment_lease_permitted': _environment_last_permitted,
           'environment_transmission_state': environment_transmission_state,
           'transmission_diagnostic': dict(transmission_diagnostic),
           'watchdog_first_revocation': watchdog_first_revocation,
           'watchdog_last_revocation': watchdog_last_revocation,
           'watchdog_first_unplanned_revocation': watchdog_first_unplanned_revocation,
           'native_snapshot': dict(native_snapshot_diagnostic),
           'watchdog_scheduling': dict(watchdog_scheduling),
           'probe_scheduling': dict(probe_scheduling),
           'fixed_exit_sources': {source:dict(counts) for source,counts in fixed_source_diagnostics.items()},
           'exit_noresult_pause': ({'state':'suspended','generation':exit_noresult_pause['generation'],
               'scope_kind':exit_noresult_pause['scope_kind'],
               'scope_signature':exit_noresult_pause['scope_signature'],
               'seconds_remaining':max(0.,exit_noresult_pause['deadline_mono']-time.monotonic()),
               'forwards_application_bytes':False} if exit_noresult_pause is not None else None),
           'exit_noresult_pause_counts':dict(exit_noresult_pause_counts),
           'application_transmission_state':('permitted' if ok else 'suspended' if exit_noresult_pause is not None or _native_snapshot_continuity.pause is not None and not _native_snapshot_continuity.pause['hard_failed'] else 'denied'),
           'scope_pause_counts': dict(scope_pause_counts),
           'environment_last_failure': _environment_last_failure,
           'environment_failure_events': list(_environment_failure_events),
           'guard_failure_events': list(_guard_failure_events),
           'environment_registration_count': native_snapshot_diagnostic.get('registration_count',0) if native_snapshot_diagnostic.get('mode')=='native' else len(_environment_registry.records) if _environment_registry else 0,
           'scope_route_events': list(_scope_route_events),
           'peer_attribution':_private_peer_worker.diagnostics() if _private_peer_worker else None,
           'timing': {'cache_seconds': EXIT_CACHE_SECONDS,
                      'foreground_grant_reuse_seconds': EXIT_LEASE_SECONDS,
                      'lease_seconds': EXIT_LEASE_SECONDS,
                      'zero_byte_exit_noresult_pause_seconds':EXIT_NORESULT_PAUSE_SECONDS,
                      'local_watchdog_seconds': LOCAL_WATCHDOG_SECONDS,
                      'minimum_probe_start_seconds': MIN_PROBE_START_SECONDS,
                      'probe_manager': 'bounded_parallel_physical_workers',
                      'maximum_physical_probes': MAX_EXIT_PROBES,
                      'physical_probe_total_budget_seconds': FIXED_PROBE_BUDGET_SECONDS,
                      'fixed_probe_sources': list(FIXED_EXIT_SOURCES)}}
    p = ROOT / 'status.json'
    if _environment_json_writer is not None:
        # Diagnostics must not invalidate a valid grant merely because a
        # concurrent status reader holds the previous immutable snapshot.
        _environment_json_writer(p, obj)
        return
    tmp = p.with_suffix('.tmp')
    tmp.write_text(json.dumps(obj), encoding='utf-8')
    tmp.replace(p)


def configured_allowlist():
    # A malformed, missing, empty or expanded policy cannot silently allow traffic.
    obj = json.loads((ROOT / 'policy.json').read_text(encoding='utf-8'))
    values = frozenset(str(ipaddress.ip_address(v)) for v in obj['allowed_exit_ips'])
    if not values or not values.issubset(ALLOWED):
        raise ValueError('Invalid exit allowlist')
    return values


def verify_exit_sync():
    allowed = configured_allowlist()
    if (ROOT / 'hold.block').exists():
        raise RuntimeError('Manual offline hold')
    proxy = 'http://%s:%s' % CORE_PROXY
    op = urllib.request.build_opener(urllib.request.ProxyHandler({'https': proxy, 'http': proxy}))
    with op.open('https://www.cloudflare.com/cdn-cgi/trace', timeout=7) as response:
        if response.status != 200:
            raise RuntimeError('Exit check status')
        fields = dict(x.split('=', 1) for x in response.read(8192).decode('ascii').splitlines() if '=' in x)
        actual = str(ipaddress.ip_address(fields['ip']))
    if actual not in allowed:
        raise RuntimeError('Exit IP is outside allowlist')
    return actual


class FixedProbeBudgetExpired(TimeoutError):
    """No measurement arrived within the immutable physical-probe budget."""


def parse_fixed_exit_body(source, body):
    """Closed fixed-source body schemas. No dynamic host, URL or credentials."""
    if source not in FIXED_EXIT_SOURCES or type(body) is not bytes or not 0<len(body)<=8192:
        raise ValueError('Exit response body invalid')
    text=body.decode('ascii')
    if source=='cloudflare_trace':
        fields={}
        for line in text.splitlines():
            if '=' not in line:raise ValueError('Exit response body invalid')
            key,value=line.split('=',1)
            if not key or key in fields:raise ValueError('Exit response body invalid')
            fields[key]=value
        if 'ip' not in fields or not fields['ip'] or 'loc' not in fields or len(fields['loc'])!=2:
            raise ValueError('Exit response body invalid')
        value=fields['ip']
    else:
        def pairs(items):
            result={}
            for key,value in items:
                if key in result:raise ValueError('Exit response body invalid')
                result[key]=value
            return result
        data=json.loads(text,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Exit response body invalid')))
        if type(data) is not dict or set(data)!={'ip'} or type(data['ip']) is not str or not data['ip']:
            raise ValueError('Exit response body invalid')
        value=data['ip']
    if value!=value.strip():raise ValueError('Exit response body invalid')
    return str(ipaddress.ip_address(value))


def _fixed_probe_target(source):
    if source=='cloudflare_trace':return 'www.cloudflare.com','/cdn-cgi/trace'
    if source=='ipify_json':return 'api.ipify.org','/?format=json'
    raise ValueError('Unknown fixed exit source')


class _FixedProbeHTTPSConnection(http.client.HTTPSConnection):
    """Keep the one response socket owned until bounded body consumption ends.

    http.client normally closes its socket reference at getresponse() for a
    Connection: close reply even though the response file still reads it. This
    probe never reuses a connection, but needs that exact socket for deadline
    shutdown and updated remaining timeouts until the response is consumed.
    """
    _retain_response_socket = False
    def close(self):
        if self._retain_response_socket:
            return
        super().close()


def verify_fixed_exit_source(source):
    """One fresh TLS CONNECT over CORE_PROXY with a 3.5-second total budget."""
    host,request_path=_fixed_probe_target(source)
    allowed=configured_allowlist()
    if (ROOT/'hold.block').exists():raise RuntimeError('Manual offline hold')
    began=time.monotonic();deadline=began+FIXED_PROBE_BUDGET_SECONDS
    connection=_FixedProbeHTTPSConnection(CORE_PROXY[0],CORE_PROXY[1],timeout=FIXED_PROBE_BUDGET_SECONDS,
                                            context=ssl.create_default_context())
    connection.set_tunnel(host,443)
    expired=threading.Event();active_socket=[None]
    def abort_at_deadline():
        expired.set()
        sock=connection.sock or active_socket[0]
        if sock is not None:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            try:sock.close()
            except OSError:pass
    timer=threading.Timer(max(0.,deadline-time.monotonic()),abort_at_deadline);timer.daemon=True
    def phase():
        remaining=deadline-time.monotonic()
        if expired.is_set() or not 0<remaining<=FIXED_PROBE_BUDGET_SECONDS:raise FixedProbeBudgetExpired()
        connection.timeout=remaining
        if connection.sock is not None:
            active_socket[0]=connection.sock;connection.sock.settimeout(remaining)
        elif active_socket[0] is not None:active_socket[0].settimeout(remaining)
    response=None;timer.start()
    try:
        phase();connection.connect();phase()
        connection.request('GET',request_path,headers={'Accept':'text/plain' if source=='cloudflare_trace' else 'application/json','Connection':'close'})
        phase();connection._retain_response_socket=True;response=connection.getresponse();phase()
        if response.status!=200:raise RuntimeError('Exit check status')
        body=bytearray()
        while len(body)<=8192:
            phase();chunk=response.read1(min(1024,8193-len(body)))
            if not chunk:break
            body.extend(chunk)
        phase()
        actual=parse_fixed_exit_body(source,bytes(body))
        if actual not in allowed or actual not in configured_allowlist():raise RuntimeError('Exit IP is outside allowlist')
        if (ROOT/'hold.block').exists():raise RuntimeError('Manual offline hold')
        phase()
        return actual
    except Exception as error:
        # Budget exhaustion is an explicit absent result. Certificate, generic
        # TLS, HTTP or schema failure otherwise stays a hard revocation.
        if isinstance(error,FixedProbeBudgetExpired):raise
        if isinstance(error,(ssl.SSLError,urllib.error.HTTPError,ValueError,RuntimeError)):
            raise
        if (expired.is_set() or time.monotonic()>=deadline) and isinstance(error,(OSError,http.client.RemoteDisconnected,http.client.IncompleteRead)):
            raise FixedProbeBudgetExpired() from None
        raise
    finally:
        timer.cancel()
        if response is not None:response.close()
        connection._retain_response_socket=False
        connection.close()


async def close_all():
    global revocation_generation, scope_pause_started, scope_pause_signature, scope_pause_generation, scope_pause_deadline, scope_pause_phase, scope_pause_recovery_after, exit_noresult_pause
    # Also invalidate clients still waiting for an upstream connection/reply.
    revocation_generation += 1
    _native_snapshot_continuity.clear()
    exit_noresult_pause = None
    scope_pause_started = scope_pause_signature = scope_pause_generation = None
    scope_pause_deadline = scope_pause_phase = scope_pause_recovery_after = None
    for writer in list(connections):
        try:
            writer.transport.abort()
        except Exception:
            try:
                writer.close()
            except Exception:
                pass


def require_generation(generation, local=False):
    if generation != revocation_generation:
        raise RuntimeError('Connection permission was revoked')
    if (last_exit is None or last_ok <= 0 or
            not 0 <= time.monotonic() - last_ok < EXIT_LEASE_SECONDS):
        raise RuntimeError('Connection permission expired')
    if local and ((ROOT / 'hold.block').exists() or last_exit not in configured_allowlist()):
        raise RuntimeError('Local exit policy no longer permits this connection')
    if not environment_permitted():
        raise RuntimeError('Private environment lease expired or failed')


def require_network_generation(generation):
    """Only an independent fixed-exit probe can run without an env grant."""
    if generation != revocation_generation:
        raise RuntimeError('Connection permission was revoked')
    if (last_exit is None or last_ok <= 0 or
            not 0 <= time.monotonic() - last_ok < EXIT_LEASE_SECONDS):
        raise RuntimeError('Connection permission expired')
    if (ROOT / 'hold.block').exists() or last_exit not in configured_allowlist():
        raise RuntimeError('Local exit policy no longer permits this connection')


def native_browser_pause_eligible():
    """Only the independently verified native-browser-only scope may pause."""
    observation=native_admission_observation()
    return (observation is not None and observation.get('state')=='permitted'
        and native_snapshot_diagnostic.get('mode')=='native'
        and type(native_snapshot_diagnostic.get('registration_count')) is int
        and native_snapshot_diagnostic['registration_count']>0)


def verified_exit_pause_scope():
    """A fresh exact receipt for supported fully verified registered scopes.

    The existing snapshot verifies original runtime/lease deadlines, process
    identities, fixed source contracts and generation. Its signature includes
    exact target/monitor creation identities and nonces. Publishing/reading
    this descriptor never renews the original four-second evidence.
    """
    observation=native_admission_observation()
    if (not isinstance(observation,dict) or observation.get('state')!='permitted'
            or type(native_snapshot_diagnostic.get('registration_count')) is not int
            or native_snapshot_diagnostic['registration_count']<=0):return None
    signature=observation.get('signature')
    if type(signature) is not str or len(signature)!=64 or any(c not in 'abcdef0123456789' for c in signature):return None
    kind=native_snapshot_diagnostic.get('scope_kind');mode=native_snapshot_diagnostic.get('mode')
    if not ((kind=='browser-only' and mode=='native')
            or (kind in ('native-only','mixed') and mode=='environment')):return None
    return {'kind':kind,'signature':signature}


def publish_noresult_pause_status():
    anchor=exit_noresult_pause
    if anchor is not None and not anchor.get('published',False):
        try:status(False,'Exit measurement absent; application transmission suspended')
        except Exception:return
        if exit_noresult_pause is anchor:anchor['published']=True


def noresult_pause_observation(generation):
    """Observe a bounded absence, never mint or refresh network permission.

    The anchor is the original IP grant's expiry, not first polling, status
    publication, a failed probe, or a new client connection. A real revocation
    clears this anchor in close_all(), making old connections unrecoverable.
    Environment permission must be checked separately by every caller.
    """
    global exit_noresult_pause
    now = time.monotonic()
    if generation != revocation_generation:
        raise RuntimeError('Connection permission was revoked')
    policy=tuple(sorted(configured_allowlist()))
    if (ROOT / 'hold.block').exists() or last_exit not in policy:
        raise RuntimeError('Local exit policy no longer permits this connection')
    if (type(last_ok) not in (int, float) or not math.isfinite(last_ok) or last_ok <= 0
            or not 0 <= now - last_ok):
        raise RuntimeError('Connection permission unavailable')
    if now - last_ok < EXIT_LEASE_SECONDS:
        return 'permitted'
    scope=verified_exit_pause_scope()
    if scope is None:
        raise RuntimeError('Exit absence pause scope unsupported or invalid')
    expiry = last_ok + EXIT_LEASE_SECONDS
    if exit_noresult_pause is None:
        exit_noresult_pause = {'generation': generation, 'exit': last_exit,
            'original_checked_mono': last_ok, 'expired_mono': expiry,
            'deadline_mono': expiry + EXIT_NORESULT_PAUSE_SECONDS,'published':False,
            'scope_kind':scope['kind'],'scope_signature':scope['signature'],'allowlist':policy}
        exit_noresult_pause_counts['started'] += 1
    anchor = exit_noresult_pause
    if (anchor['generation'] != generation or anchor['exit'] != last_exit
            or anchor['original_checked_mono'] != last_ok
            or anchor['scope_kind']!=scope['kind'] or anchor['scope_signature']!=scope['signature']
            or anchor['allowlist']!=policy):
        raise RuntimeError('Exit absence pause anchor changed')
    if now >= anchor['deadline_mono']:
        raise RuntimeError('Exit absence pause expired')
    publish_noresult_pause_status()
    return 'suspended'


async def wait_fresh_network_generation(generation):
    """Return only with an actual unexpired grant; expiry waits without writes."""
    while True:
        # Environment denial is never converted into an IP no-result pause.
        state = transmission_state()
        if state == 'denied':
            raise RuntimeError('Private environment lease expired or failed')
        if state=='suspended' and snapshot_pause_scope(generation) is not None:
            # Both proofs may currently be unavailable, but neither deadline
            # is extended and no application byte/new upstream may proceed.
            await asyncio.sleep(.02);continue
        result = noresult_pause_observation(generation)
        if result == 'permitted':
            try:require_network_generation(generation)
            except RuntimeError:
                # Expiry between the two clock samples is another absence,
                # not a hard failure. Rechecking generation/hold/allowlist in
                # this observation still propagates all real revocations.
                if noresult_pause_observation(generation)=='suspended':continue
                raise
            else:return
        if state != 'permitted':
            raise RuntimeError('Environment transition cannot extend exit absence pause')
        # At most one 64KiB read is held by each pump, plus the StreamReader's
        # bounded high-water buffer. No data is forwarded and no new upstream
        # connection is established while the previous IP proof is expired.
        await asyncio.sleep(.02)


async def wait_environment(generation=None):
    while True:
        if generation is not None:
            await wait_fresh_network_generation(generation)
        elif (ROOT / 'hold.block').exists():
            raise RuntimeError('Manual offline hold')
        state = transmission_state()
        if state == 'permitted':
            # Identity/file checks can themselves take time. They must not
            # leave an already expired exit grant valid for the next write.
            if generation is not None:
                await wait_fresh_network_generation(generation)
            elif (ROOT / 'hold.block').exists():
                raise RuntimeError('Manual offline hold')
            return
        if state != 'suspended':
            raise RuntimeError('Private environment lease expired or failed')
        # No application bytes or new upstream connection are issued here.
        # A single bounded read chunk per direction is retained by pump().
        await asyncio.sleep(.02)


async def probe_environment(probe_only):
    if probe_only:
        if transmission_state() not in ('permitted', 'suspended'):
            raise RuntimeError('Private environment lease expired or failed')
    else:
        await wait_environment()


def transient_probe_error(error):
    """Only transport failures may leave an existing fresh grant untouched."""
    if isinstance(error,(ssl.SSLEOFError,ssl.SSLZeroReturnError)):
        return True
    if isinstance(error, (ssl.SSLError, urllib.error.HTTPError)):
        return False
    if isinstance(error, urllib.error.URLError):
        reason = error.reason
        if isinstance(reason,(ssl.SSLEOFError,ssl.SSLZeroReturnError)):
            return True
        return isinstance(reason, OSError) and not isinstance(reason, (ssl.SSLError, urllib.error.HTTPError))
    return isinstance(error, (TimeoutError, ConnectionError, http.client.RemoteDisconnected))


def completed_exit_probe(closing):
    # The timestamp belongs to the actual completed fixed HTTPS operation,
    # never the later scheduler/status-file publication.
    global last_probe_started, _probe_endpoint_sequence
    with _probe_start_lock:
        delay = MIN_PROBE_START_SECONDS - (time.monotonic() - last_probe_started)
        while last_probe_started > 0 and delay > 0:
            if closing.wait(delay):
                raise RuntimeError('Exit probe manager stopped')
            delay = MIN_PROBE_START_SECONDS - (time.monotonic() - last_probe_started)
        if closing.is_set():
            raise RuntimeError('Exit probe manager stopped')
        started_at = time.monotonic()
        last_probe_started = started_at
        source=FIXED_EXIT_SOURCES[_probe_endpoint_sequence % len(FIXED_EXIT_SOURCES)]
        _probe_endpoint_sequence+=1
    with _probe_endpoint_lock:fixed_source_diagnostics[source]['started']+=1
    try:
        actual=verify_fixed_exit_source(source)
        with _probe_endpoint_lock:fixed_source_diagnostics[source]['succeeded']+=1
        return actual,started_at,time.monotonic()
    except Exception as error:
        key='transport_no_result' if transient_probe_error(error) else 'hard_failed'
        with _probe_endpoint_lock:fixed_source_diagnostics[source][key]+=1
        raise


class ExitProbeManager:
    """One guard-owned scheduler, with at most two actual blocking probes.

    Raw concurrent futures occupy slots until their real worker finishes.
    Cancelling an asyncio caller cannot free a running blocking worker's slot.
    """
    def __init__(self):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_EXIT_PROBES,
                                                              thread_name_prefix='fixed-exit-probe')
        self.pending = {}
        self.success_sequence = 0
        self.failure_sequence = 0
        self.last_failure = None
        self.started_sequence = 0
        self.closed = False
        self.closing = threading.Event()
        self.task = None

    def publish(self, ok, reason, actual=None):
        try:
            status(ok, reason, actual)
        except Exception as error:
            # Status output is diagnostic; it never extends an in-memory grant.
            record_guard_failure('exit_probe_status', error)

    async def revoke(self, error):
        global last_ok, last_exit
        record_guard_failure('exit_verification', error)
        self.failure_sequence += 1
        self.last_failure = error
        last_ok = 0; last_exit = None
        await close_all()
        self.publish(False, 'Exit unavailable, unverified, held, expired, or outside allowlist')

    async def complete(self, future, generation):
        global last_ok, last_exit, exit_noresult_pause
        try:
            actual, started_at, completed_at = future.result()
            probe_scheduling['completed']+=1
            duration_ms=(completed_at-started_at)*1000;lag_ms=(time.monotonic()-completed_at)*1000
            probe_scheduling.update(last_duration_ms=round(duration_ms,3),max_duration_ms=round(max(probe_scheduling['max_duration_ms'],duration_ms),3),last_collection_lag_ms=round(lag_ms,3),max_collection_lag_ms=round(max(probe_scheduling['max_collection_lag_ms'],lag_ms),3))
        except Exception as error:
            if transient_probe_error(error):
                # No result is no new grant. Existing permission expires at its
                # original four-second timestamp, independently of this task.
                record_guard_failure('exit_probe_transport', error)
                return
            await self.revoke(error)
            return
        try:
            allowed = configured_allowlist()
            if actual not in allowed:
                raise RuntimeError('Exit IP is outside allowlist')
            if (generation != revocation_generation or not 0 <= completed_at - started_at < EXIT_LEASE_SECONDS
                    or not 0 <= time.monotonic() - completed_at < EXIT_LEASE_SECONDS):
                record_guard_failure('exit_probe_stale', RuntimeError('Probe permission was revoked while checking'))
                return
            if (ROOT / 'hold.block').exists():
                raise RuntimeError('Manual offline hold')
            state = transmission_state()
            if state not in ('permitted', 'suspended'):
                raise RuntimeError('Private environment lease expired or failed')
            # Identity/registry reads can consume time; a concurrent revocation
            # must still win before a completed probe creates a new grant.
            if generation != revocation_generation:
                record_guard_failure('exit_probe_stale', RuntimeError('Probe permission was revoked while checking'))
                return
            if actual not in configured_allowlist() or (ROOT / 'hold.block').exists():
                raise RuntimeError('Exit policy changed during verification')
            if (generation != revocation_generation
                    or not 0 <= time.monotonic() - completed_at < EXIT_LEASE_SECONDS):
                record_guard_failure('exit_probe_stale', RuntimeError('Probe permission was revoked while checking'))
                return
            if (state=='suspended' and snapshot_pause_scope(generation) is not None
                    and _native_snapshot_continuity.pause.get('exit') is not None
                    and actual!=_native_snapshot_continuity.pause['exit']):
                raise RuntimeError('Snapshot pause exit recovery invalid')
            if completed_at <= last_ok:
                # Reordered physical completions never rewind a fresher grant.
                return
            if exit_noresult_pause is not None:
                anchor=exit_noresult_pause
                scope=verified_exit_pause_scope()
                if scope is None and state=='suspended':scope=snapshot_pause_scope(generation)
                # A late or different-IP success cannot resurrect transports
                # retained under the old proof. A new generation may recover
                # only through a subsequent independent fresh probe.
                if (anchor['generation'] != generation or actual != anchor['exit']
                        or time.monotonic() >= anchor['deadline_mono']
                        or scope is None or scope['kind']!=anchor['scope_kind']
                        or scope['signature']!=anchor['scope_signature']
                        or tuple(sorted(configured_allowlist()))!=anchor['allowlist']):
                    raise RuntimeError('Exit absence pause recovery invalid')
            last_exit = actual
            last_ok = completed_at
            if exit_noresult_pause is not None:
                exit_noresult_pause_counts['resumed'] += 1
                exit_noresult_pause = None
            self.success_sequence += 1
            self.publish(state == 'permitted', 'Verified pinned residential exit'
                         if state == 'permitted' else 'Pinned exit verified; application transmission suspended', actual)
        except Exception as error:
            await self.revoke(error)

    async def run(self):
        try:
            while True:
                # Observe completed failures before launching another probe.
                # An outside-allowlist result revokes even when another probe
                # also returned a valid result during the same scheduler turn.
                completed = [(future, details) for future, details in self.pending.items() if future.done()]
                for future, generation in completed:
                    self.pending.pop(future)
                    await self.complete(future, generation)
                now = time.monotonic()
                if (len(self.pending) < MAX_EXIT_PROBES and
                        (last_probe_started <= 0 or now - last_probe_started >= MIN_PROBE_START_SECONDS)):
                    try:
                        allowed = configured_allowlist()
                        if (ROOT / 'hold.block').exists():
                            raise RuntimeError('Manual offline hold')
                        if transmission_state() not in ('permitted', 'suspended'):
                            raise RuntimeError('Private environment lease expired or failed')
                        if last_exit is not None and last_exit not in allowed:
                            raise RuntimeError('Local exit policy no longer permits this connection')
                    except Exception:
                        # The independent local watchdog owns policy failure
                        # revocation, avoiding repeated generation increments.
                        await watchdog_step()
                    else:
                        self.started_sequence += 1
                        future = self.executor.submit(completed_exit_probe, self.closing)
                        self.pending[future] = revocation_generation
                await asyncio.sleep(LOCAL_WATCHDOG_SECONDS)
        finally:
            self.closed = True
            self.closing.set()
            # Do not cancel raw futures or free their slots early. The caller
            # waits until up to two blocking workers actually finish; the
            # existing socket timeout is per operation, not a hard total time.
            self.executor.shutdown(wait=False, cancel_futures=False)
            while any(not future.done() for future in self.pending):
                try:
                    await asyncio.shield(asyncio.sleep(LOCAL_WATCHDOG_SECONDS))
                except asyncio.CancelledError:
                    continue
            self.pending.clear()
            self.executor.shutdown(wait=True, cancel_futures=False)


def ensure_probe_manager():
    global _probe_manager
    if _probe_manager is None or (_probe_manager.closed and _probe_manager.task.done()):
        _probe_manager = ExitProbeManager()
        _probe_manager.task = asyncio.create_task(_probe_manager.run())
    return _probe_manager


async def verify_exit(force=False, *, probe_only=False):
    """Never wait for browser readiness while owning the exit-probe lock."""
    global last_ok, last_exit
    if not probe_only:
        try:
            await wait_environment()
            generation = revocation_generation
            # Use the same strict live grant as pump(). Independent forced
            # probes continue; cached admission never updates its timestamp.
            if not force and last_exit is not None:
                try:
                    require_network_generation(generation)
                    return last_exit
                except RuntimeError:
                    pass
        except Exception as error:
            record_guard_failure('local_admission', error)
            last_ok = 0; last_exit = None
            await close_all()
            status(False, 'Local exit policy refused admission')
            raise
    # The internal operation may revalidate only the fixed public exit while
    # app data is suspended. It never waits on application environment state.
    result = await _verify_exit_probe(force, probe_only=True)
    generation = revocation_generation
    if not probe_only:
        await wait_environment(generation)
    return result


async def _verify_exit_probe(force=False, *, probe_only=True):
    # Foreground requests consume a strict fresh grant or wait for the one
    # independent manager. They never queue another blocking public probe.
    manager = ensure_probe_manager()
    baseline = manager.success_sequence
    failure_baseline = manager.failure_sequence
    waiting_generation = revocation_generation
    deadline = time.monotonic() + EXIT_PROBE_WAIT_SECONDS
    while True:
        if manager.closed or manager.task.done():
            raise RuntimeError('Exit probe manager is unavailable')
        if manager.failure_sequence > failure_baseline:
            raise manager.last_failure
        if waiting_generation != revocation_generation:
            raise RuntimeError('Probe permission was revoked while checking')
        if (ROOT / 'hold.block').exists():
            raise RuntimeError('Manual offline hold')
        await probe_environment(probe_only)
        if snapshot_pause_scope(waiting_generation) is not None:
            await asyncio.sleep(LOCAL_WATCHDOG_SECONDS);continue
        allowed = configured_allowlist()
        if last_exit is not None and last_exit not in allowed:
            await manager.revoke(RuntimeError('Local exit policy no longer permits this connection'))
            raise RuntimeError('Local exit policy no longer permits this connection')
        if last_exit is not None and last_ok > 0 and time.monotonic()-last_ok >= EXIT_LEASE_SECONDS:
            if transmission_state() != 'permitted':
                raise RuntimeError('Environment transition cannot extend exit absence pause')
            noresult_pause_observation(waiting_generation)
        if last_exit in allowed and last_ok > 0 and (not force or manager.success_sequence > baseline):
            generation = revocation_generation
            try:
                require_network_generation(generation)
            except RuntimeError:
                pass
            else:
                if not probe_only:
                    await wait_environment(generation)
                return last_exit
        if time.monotonic() >= deadline:
            # Already accepted local client sockets may wait for the same
            # global absence anchor, without opening an upstream or renewing
            # the four-second permission. Startup without a previous proof
            # retains its original, shorter wait limit.
            if transmission_state() != 'permitted' or last_exit is None:
                raise RuntimeError('Exit verification timed out')
            if noresult_pause_observation(waiting_generation) != 'suspended':
                raise RuntimeError('Exit verification timed out')
        await asyncio.sleep(LOCAL_WATCHDOG_SECONDS)


async def watchdog_step():
    """Bound old permission without waiting for a stalled network probe lock."""
    global last_ok, last_exit, watchdog_blocked, watchdog_first_revocation, watchdog_last_revocation, watchdog_first_unplanned_revocation
    try:
        allowed = configured_allowlist()
        state = transmission_state()
        blocked = ((ROOT / 'hold.block').exists() or state == 'denied' or
                   (last_exit is not None and
                    (last_exit not in allowed or type(last_ok) not in (int,float)
                     or not math.isfinite(last_ok) or last_ok <= 0 or time.monotonic()<last_ok)))
        reason = ('manual_hold' if (ROOT / 'hold.block').exists() else
                  'environment_denied' if state == 'denied' else
                  'exit_outside_allowlist' if last_exit is not None and last_exit not in allowed else
                  'exit_lease_expired')
        if not blocked and state=='suspended' and snapshot_pause_scope(revocation_generation) is not None:
            # Snapshot pause ends at the old environment receipt's four-second
            # deadline; it does not mint an exit grant or extend a 45s anchor.
            watchdog_blocked=False
            return False
        if not blocked and last_exit is not None and time.monotonic()-last_ok >= EXIT_LEASE_SECONDS:
            if state != 'permitted':
                blocked=True
                reason='environment_transition_during_exit_absence'
            else:
                try:
                    noresult_pause_observation(revocation_generation)
                except Exception:
                    blocked=True
                    reason='exit_absence_pause_expired_or_invalid'
                else:
                    # Keep sockets, not permission. Forwarding paths still
                    # wait for a fresh four-second actual exit measurement.
                    watchdog_blocked=False
                    publish_noresult_pause_status()
                    return False
    except Exception:
        blocked = True
        reason = 'local_policy_unavailable'
    if not blocked:
        watchdog_blocked = False
        return False
    if watchdog_blocked:
        return False
    record_guard_failure('watchdog_revocation', RuntimeError('Local policy or fresh exit lease revoked'))
    watchdog_last_revocation = {'at': time.time(), 'reason': reason,
        'exit_lease_age_seconds': round(time.monotonic()-last_ok, 4) if last_ok > 0 else None,
        'transmission': dict(transmission_diagnostic)}
    if watchdog_first_revocation is None:watchdog_first_revocation=dict(watchdog_last_revocation)
    if reason!='manual_hold' and watchdog_first_unplanned_revocation is None:
        watchdog_first_unplanned_revocation=dict(watchdog_last_revocation)
    watchdog_blocked = True
    last_ok = 0
    last_exit = None
    await close_all()
    try:
        status(False, 'Local policy or fresh exit lease revoked')
    except Exception:
        pass
    return True


async def watchdog():
    expected=time.monotonic()
    while True:
        now=time.monotonic();lag=max(0.,now-expected)*1000
        watchdog_scheduling['samples']+=1;watchdog_scheduling['last_lag_ms']=round(lag,3)
        watchdog_scheduling['max_lag_ms']=round(max(watchdog_scheduling['max_lag_ms'],lag),3)
        await watchdog_step()
        expected=time.monotonic()+LOCAL_WATCHDOG_SECONDS
        await asyncio.sleep(LOCAL_WATCHDOG_SECONDS)


async def pump(reader, writer, generation):
    try:
        while True:
            b = await reader.read(65536)
            if not b:
                break
            await wait_environment(generation)
            writer.write(b)
            await writer.drain()
            # Buffered reads/drains must yield to the independent probe owner.
            # Every following chunk still repeats the live policy checks.
            await asyncio.sleep(0)
    finally:
        writer.close()


async def bounded_core_reply(reader):
    reply=bytearray()
    while len(reply)<=32768:
        byte=await reader.read(1)
        if not byte:raise ConnectionError('Pinned upstream closed before proxy reply')
        reply.extend(byte)
        if reply.endswith(b'\r\n\r\n'):
            if len(reply)>32768:break
            return bytes(reply)
    raise RuntimeError('Pinned upstream proxy reply too large')


async def wait_core_connect_reply(reader,generation,healthy_timeout=12.):
    """Bound reply waits, excluding a verified native-only no-result pause.

    No response is forwarded here. The healthy budget remains 12s; total wall
    time is also capped at healthy_budget+45s, so repeated recoveries cannot
    roll the reply deadline indefinitely. Unknown/legacy scopes keep the old
    twelve-second hard timeout.
    """
    if verified_exit_pause_scope() is None:
        return await asyncio.wait_for(bounded_core_reply(reader),healthy_timeout)
    pending=asyncio.create_task(bounded_core_reply(reader))
    started=previous=time.monotonic();healthy_remaining=healthy_timeout;previous_suspended=False
    wall_deadline=started+healthy_timeout+EXIT_NORESULT_PAUSE_SECONDS
    try:
        while True:
            now=time.monotonic()
            if not 0<=now-previous or now>=wall_deadline:
                raise TimeoutError('Pinned upstream proxy reply timed out')
            state=transmission_state()
            if state=='denied':raise RuntimeError('Private environment lease expired or failed')
            try:require_network_generation(generation)
            except RuntimeError:
                if state=='suspended' and snapshot_pause_scope(generation) is not None:
                    suspended=True
                elif state!='permitted' or noresult_pause_observation(generation)!='suspended':raise
                else:suspended=True
            else:suspended=state=='suspended' and snapshot_pause_scope(generation) is not None
            if not previous_suspended:healthy_remaining-=now-previous
            if healthy_remaining<=0:raise TimeoutError('Pinned upstream proxy reply timed out')
            previous=now;previous_suspended=suspended
            if pending.done():
                # Physical EOF/reset remains an actual upstream failure even
                # while permission is paused; it cannot be repaired locally.
                result=pending.result()
                if not suspended:
                    try:require_network_generation(generation)
                    except RuntimeError:
                        if noresult_pause_observation(generation)!='suspended':raise
                    else:return result
            await asyncio.sleep(min(.02,healthy_remaining,max(0.,wall_deadline-time.monotonic())))
    finally:
        if not pending.done():pending.cancel()
        await asyncio.gather(pending,return_exceptions=True)


async def client(reader, writer, initial_header=None):
    upstream = None
    connected = False
    phase = 'read_proxy_header'
    connections.add(writer)
    try:
        header = initial_header if initial_header is not None else await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 15)
        if len(header) > 32768:
            raise ValueError('Header too large')
        first = header.split(b'\r\n', 1)[0].decode('ascii')
        method, target, version = first.split(' ', 2)
        if version not in ['HTTP/1.1', 'HTTP/1.0']:
            raise ValueError('HTTP version')
        if method.upper() != 'CONNECT' and not target.startswith('http://'):
            raise ValueError('Not an explicit proxy request')
        phase = 'verify_exit'
        await verify_exit()
        if writer.is_closing():
            raise RuntimeError('Client connection was already revoked')
        generation = revocation_generation
        await wait_environment(generation)
        granted_connections.add(writer)
        phase = 'connect_core'
        remote_reader, upstream = await asyncio.wait_for(asyncio.open_connection(*CORE_PROXY), 5)
        connections.add(upstream)
        await wait_environment(generation)
        upstream.write(header)
        await upstream.drain()
        if method.upper() == 'CONNECT':
            phase = 'await_core_connect_reply'
            reply = await wait_core_connect_reply(remote_reader,generation)
            if len(reply) > 32768 or reply.split(b' ', 2)[1] != b'200':
                raise RuntimeError('Pinned upstream refused tunnel')
            await wait_environment(generation)
            writer.write(reply)
            await writer.drain()
        await wait_environment(generation)
        connected = True
        phase = 'forward_stream'
        tasks = [asyncio.create_task(pump(reader, upstream, generation)),
                 asyncio.create_task(pump(remote_reader, writer, generation))]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        for outcome in outcomes:
            if isinstance(outcome, Exception):
                record_guard_failure('forward_stream', outcome)
    except Exception as error:
        record_guard_failure(phase, error)
        if not connected and scope_pause_phase is None and not writer.is_closing():
            try:
                writer.write(b'HTTP/1.1 503 Claude network locked\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                await writer.drain()
            except Exception:
                pass
    finally:
        granted_connections.discard(writer)
        for w in (writer, upstream):
            if w is not None:
                connections.discard(w)
                w.close()


def normalized_host(host):
    host = host.rstrip('.').lower()
    if not host or any(c.isspace() or ord(c) < 32 for c in host):
        raise ValueError('Invalid host')
    return host.encode('idna').decode('ascii')


def protected_host(host):
    host = normalized_host(host)
    domains = set(PROTECTED_DOMAINS)
    path = ROOT / 'browser-domains.json'
    if path.exists():
        values = json.loads(path.read_text(encoding='utf-8-sig'))
        if isinstance(values, dict):
            values = values.get('protected_domains', values.get('domains'))
        if not isinstance(values, list) or not values or not all(isinstance(v, str) for v in values):
            raise ValueError('Invalid protected domain policy')
        domains.update(normalized_host(v) for v in values)
    return any(host == domain or host.endswith('.' + domain) for domain in domains)


def authority(value, default_port):
    parsed = urlsplit('//' + value)
    if parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
        raise ValueError('Invalid authority')
    host = normalized_host(parsed.hostname or '')
    port = parsed.port or default_port
    if not 1 <= port <= 65535:
        raise ValueError('Invalid port')
    return host, port


def parse_normal_request(header):
    if len(header) > 32768 or not header.endswith(b'\r\n\r\n'):
        raise ValueError('Invalid request header')
    lines = header[:-4].split(b'\r\n')
    method, target, version = lines[0].decode('ascii').split(' ')
    if version not in ('HTTP/1.0', 'HTTP/1.1') or not method.isalpha():
        raise ValueError('Invalid request line')
    method = method.upper()
    values = {}
    for line in lines[1:]:
        if line[:1] in (b' ', b'\t') or b':' not in line:
            raise ValueError('Invalid header field')
        key, value = line.split(b':', 1)
        key = key.decode('ascii').lower()
        if not key or any(not (c.isalnum() or c in "!#$%&'*+-.^_`|~") for c in key):
            raise ValueError('Invalid header name')
        value = value.decode('latin-1').strip()
        if any(ord(c) < 32 and c != '\t' for c in value):
            raise ValueError('Invalid header value')
        if key in ('host', 'content-length', 'transfer-encoding') and key in values:
            raise ValueError('Ambiguous request headers')
        values[key] = value
    if method == 'CONNECT':
        host, port = authority(target, 443)
        scheme = 'https'
        origin = None
    else:
        parsed = urlsplit(target)
        if parsed.scheme.lower() != 'http' or not parsed.netloc or parsed.fragment:
            raise ValueError('Use CONNECT for HTTPS')
        host, port = authority(parsed.netloc, 80)
        scheme = 'http'
        origin = parsed.path or '/'
        if parsed.query:
            origin += '?' + parsed.query
    protected = protected_host(host)
    if 'host' in values:
        host_header, _ = authority(values['host'], 443 if scheme == 'https' else 80)
        protected = protected or protected_host(host_header)
    transfer = values.get('transfer-encoding', '').lower()
    length = values.get('content-length', '0')
    if transfer and (transfer != 'chunked' or 'content-length' in values):
        raise ValueError('Unsupported request framing')
    if not length.isascii() or not length.isdecimal() or len(length) > 18:
        raise ValueError('Invalid content length')
    return {'method': method, 'host': host, 'port': port, 'scheme': scheme,
            'origin': origin, 'version': version, 'lines': lines[1:],
            'protected': protected, 'chunked': transfer == 'chunked', 'length': int(length)}


def windows_proxy_settings():
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings') as key:
        def value(name, default):
            try:
                return winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                return default
        return {'enabled': bool(value('ProxyEnable', 0)), 'server': value('ProxyServer', ''),
                'override': value('ProxyOverride', ''), 'pac': value('AutoConfigURL', ''),
                'autodetect': bool(value('AutoDetect', 0))}


def bypass_proxy(host, port, rules):
    for raw in rules.split(';'):
        pattern = raw.strip().lower().rstrip('.')
        if not pattern:
            continue
        if pattern == '<local>':
            if '.' not in host and ':' not in host:
                return True
        elif fnmatch.fnmatchcase(host, pattern) or fnmatch.fnmatchcase('%s:%s' % (host, port), pattern):
            return True
    return False


def normal_route(request, settings):
    # PAC/WPAD cannot be re-evaluated safely here. Never silently replace them
    # or an invalid configured proxy with a DIRECT connection.
    if settings.get('pac') or settings.get('autodetect'):
        raise RuntimeError('System automatic proxy mode is not supported by the normal router')
    if not settings['enabled']:
        return None
    raw = settings.get('server', '').strip()
    if not raw:
        raise ValueError('Enabled system proxy is missing its address')
    if '=' in raw:
        entries = {}
        for part in raw.split(';'):
            if not part.strip():
                continue
            key, value = part.strip().split('=', 1)
            if key.lower() in entries:
                raise ValueError('Duplicate proxy protocol')
            entries[key.lower()] = value.strip()
        raw = entries.get(request['scheme'], '')
        if not raw:
            raise ValueError('No supported system proxy for this protocol')
    if '://' not in raw:
        raw = 'http://' + raw
    parsed = urlsplit(raw)
    if parsed.scheme.lower() != 'http' or not parsed.netloc:
        raise ValueError('Unsupported system proxy type')
    endpoint = authority(parsed.netloc, 80)
    if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Invalid system proxy address')
    host, port = endpoint
    if port in (NORMAL_LISTEN[1], LISTEN[1], CORE_PROXY[1]):
        # Reject reserved ports before DNS, including aliases to loopback.
        raise ValueError('Recursive or reserved local proxy address')
    if bypass_proxy(request['host'], request['port'], settings.get('override', '')):
        return None
    return endpoint


def plain_header(request, absolute, original):
    first = original.split(b'\r\n', 1)[0] if absolute else (
        '%s %s %s' % (request['method'], request['origin'], request['version'])).encode('ascii')
    fields = [line for line in request['lines']
              if line.split(b':', 1)[0].lower() not in (b'connection', b'proxy-connection', b'proxy-authorization')]
    # One HTTP request per connection prevents a later pipelined protected
    # destination from inheriting a previously approved normal proxy route.
    return b'\r\n'.join([first] + fields + [b'Connection: close', b'Proxy-Connection: close', b'', b''])


async def normal_pump(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                return
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def request_body(reader, writer, request):
    async def copy_exact(count):
        while count:
            data = await reader.readexactly(min(count, 65536))
            writer.write(data)
            await writer.drain()
            count -= len(data)
    if not request['chunked']:
        await copy_exact(request['length'])
        return
    while True:
        line = await reader.readuntil(b'\r\n')
        size_text = line[:-2].split(b';', 1)[0]
        if (len(line) > 8192 or any(c < 32 or c == 127 for c in line[:-2]) or
                not size_text or any(c not in b'0123456789abcdefABCDEF' for c in size_text)):
            raise ValueError('Invalid chunk framing')
        size = int(size_text, 16)
        writer.write(line)
        if not size:
            total = 0
            while True:
                trailer = await reader.readuntil(b'\r\n')
                total += len(trailer)
                if total > 32768 or (trailer != b'\r\n' and b':' not in trailer):
                    raise ValueError('Invalid chunk trailer')
                writer.write(trailer)
                await writer.drain()
                if trailer == b'\r\n':
                    return
        await copy_exact(size)
        if await reader.readexactly(2) != b'\r\n':
            raise ValueError('Invalid chunk terminator')
        writer.write(b'\r\n')
        await writer.drain()


async def normal_client(reader, writer):
    upstream = None
    started = False
    tasks = []
    normal_connections.add(writer)
    try:
        header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 15)
        request = parse_normal_request(header)
        if request['protected'] or await private_environment_peer_async(writer):
            normal_connections.discard(writer)
            await client(reader, writer, initial_header=header)
            return
        if request['port'] in (NORMAL_LISTEN[1], LISTEN[1], CORE_PROXY[1]):
            raise ValueError('Reserved local router port')
        endpoint = normal_route(request, windows_proxy_settings())
        remote_reader, upstream = await asyncio.wait_for(
            asyncio.open_connection(*(endpoint or (request['host'], request['port']))), 10)
        normal_connections.add(upstream)
        if request['method'] == 'CONNECT':
            if endpoint:
                upstream.write(header)
                await upstream.drain()
                reply = await asyncio.wait_for(remote_reader.readuntil(b'\r\n\r\n'), 15)
                if len(reply) > 32768 or not reply.startswith((b'HTTP/1.0 ', b'HTTP/1.1 ')):
                    raise ValueError('Invalid system proxy response')
                writer.write(reply)
                await writer.drain()
                started = True
                if reply.split(b' ', 2)[1] != b'200':
                    return
            else:
                writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
                await writer.drain()
                started = True
            tasks = [asyncio.create_task(normal_pump(reader, upstream)),
                     asyncio.create_task(normal_pump(remote_reader, writer))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        else:
            upstream.write(plain_header(request, endpoint is not None, header))
            await upstream.drain()
            started = True
            body_task = asyncio.create_task(request_body(reader, upstream, request))
            response_task = asyncio.create_task(normal_pump(remote_reader, writer))
            tasks = [body_task, response_task]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            if body_task in done and not response_task.done():
                await response_task
    except Exception:
        if not started:
            try:
                writer.write(b'HTTP/1.1 503 System proxy unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                await writer.drain()
            except Exception:
                pass
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for connection in (writer, upstream):
            if connection is not None:
                normal_connections.discard(connection)
                connection.close()


async def close_normal_connections():
    for writer in list(normal_connections):
        try:
            writer.transport.abort()
        except Exception:
            writer.close()


async def monitor():
    manager = ensure_probe_manager()
    try:
        await asyncio.shield(manager.task)
    except asyncio.CancelledError:
        manager.task.cancel()
        # Cleanup cannot abandon blocking workers or make their slots reusable.
        while not manager.task.done():
            try:
                await asyncio.shield(manager.task)
            except asyncio.CancelledError:
                continue
        raise


def core_start():
    global core_process
    config = json.loads((ROOT / 'runtime.json').read_text(encoding='utf-8'))
    # Never attach to an unrelated listener on either guard-owned port.
    with socket.socket() as s:
        if s.connect_ex(CORE_PROXY) == 0:
            raise RuntimeError('Dedicated core port already occupied')
    log = open(ROOT / 'core.log', 'ab')
    core_process = subprocess.Popen([config['core_executable'], '-d', str(ROOT / 'core'),
                                     '-f', str(ROOT / 'core' / 'config.yaml')],
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
    log.close()


async def serve():
    global check_lock, _native_policy_observer
    _native_policy_observer=NativePolicyObserver()
    # Install only the share-safe writer function before the first status write.
    # This registry object is never queried by the event loop.
    _native_policy_observer.registry=_native_policy_observer._registry()
    _native_policy_observer.start()
    check_lock = asyncio.Lock()
    status(False, 'Starting locked')
    # Bind the public gate first. An occupied port aborts before any core starts.
    server = await asyncio.start_server(client, *LISTEN, limit=32769)
    normal_server = None
    monitor_task = watchdog_task = None
    try:
        normal_server = await asyncio.start_server(normal_client, *NORMAL_LISTEN, limit=32769)
        core_start()
        monitor_task = asyncio.create_task(monitor())
        watchdog_task = asyncio.create_task(watchdog())
        async with server, normal_server:
            await asyncio.gather(server.serve_forever(), normal_server.serve_forever())
    finally:
        for task in (monitor_task, watchdog_task):
            if task is not None:
                task.cancel()
        await asyncio.gather(*(task for task in (monitor_task, watchdog_task) if task is not None),
                             return_exceptions=True)
        server.close()
        if normal_server:
            normal_server.close()
        await close_all()
        await close_normal_connections()
        if _private_peer_worker is not None:_private_peer_worker.close()
        if core_process and core_process.poll() is None:
            core_process.terminate()
        if _native_policy_observer is not None:
            await asyncio.to_thread(_native_policy_observer.close)
        status(False, 'Stopped')


def windows_command_line_args(command_line):
    """Parse the real Windows quoting rules without exposing process arguments."""
    from ctypes import wintypes
    if not isinstance(command_line, str) or not command_line.strip() or '\x00' in command_line:
        raise ValueError('Invalid process command line')
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    parse = shell32.CommandLineToArgvW
    parse.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    parse.restype = ctypes.POINTER(wintypes.LPWSTR)
    free = kernel32.LocalFree
    free.argtypes = [wintypes.HLOCAL]
    free.restype = wintypes.HLOCAL
    count = ctypes.c_int()
    argv = parse(command_line, ctypes.byref(count))
    if not argv:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return [argv[index] for index in range(count.value)]
    finally:
        if free(ctypes.cast(argv, wintypes.HLOCAL)):
            raise ctypes.WinError(ctypes.get_last_error())


def claude_process_snapshot():
    script = '''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$taskClaudeProcesses=@(Get-CimInstance -ClassName Win32_Process -Filter "Name='Claude.exe'" -ErrorAction Stop | Select-Object ProcessId,ExecutablePath,CommandLine)
ConvertTo-Json -InputObject $taskClaudeProcesses -Compress'''
    query = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                           capture_output=True, text=True, encoding='utf-8-sig', timeout=10,
                           creationflags=subprocess.CREATE_NO_WINDOW)
    if query.returncode != 0:
        raise RuntimeError('Process query failed')
    rows = json.loads(query.stdout)
    if not isinstance(rows, list):
        raise ValueError('Invalid process snapshot')
    return rows


def required_claude_launch_switches():
    """One source for launch arguments and validation of an existing instance."""
    return {
        '--proxy-server': 'http://%s:%s' % LISTEN,
        '--proxy-bypass-list': '<-loopback>',
        '--disable-quic': None,
        '--disable-background-timer-throttling': None,
        '--webrtc-ip-handling-policy': 'disable_non_proxied_udp',
        '--lang': 'en-US',
        '--accept-lang': 'en-US,en',
    }


def claude_launch_arguments(candidate):
    return [str(candidate)] + [key if value is None else key + '=' + value
                               for key, value in required_claude_launch_switches().items()]


def existing_claude_launch_preflight(candidate, rows=None):
    """Electron may reuse an existing main process and discard new proxy flags."""
    try:
        rows = claude_process_snapshot() if rows is None else rows
        if not isinstance(rows, list):
            raise ValueError('Invalid process snapshot')
        target = os.path.normcase(os.path.abspath(str(candidate)))
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('ExecutablePath'), str) or not row['ExecutablePath']:
                raise ValueError('Unknown process executable')
            if os.path.normcase(os.path.abspath(row['ExecutablePath'])) != target:
                continue
            argv = windows_command_line_args(row.get('CommandLine'))[1:]
            if '--' in argv:
                argv = argv[:argv.index('--')]
            process_types = [arg for arg in argv
                             if arg.partition('=')[0].lower() == '--type']
            if process_types:
                # Only known, unambiguous Electron child switches may skip the
                # main-process requirements. Unknown/case-mixed/duplicate type
                # arguments must not conceal an unsafe existing main instance.
                known_children = {'renderer', 'utility', 'gpu-process',
                                  'crashpad-handler'}
                if (len(process_types) != 1 or
                        not process_types[0].startswith('--type=') or
                        process_types[0].partition('=')[2] not in known_children):
                    raise RuntimeError('Unsafe existing Claude main process')
                continue
            expected = required_claude_launch_switches()
            found = {key: [] for key in expected}
            conflicting = {'--no-proxy-server', '--proxy-pac-url', '--proxy-auto-detect', '--enable-quic'}
            for index, arg in enumerate(argv):
                key, separator, value = arg.partition('=')
                key = key.lower()
                if key in conflicting:
                    raise RuntimeError('Unsafe existing Claude main process')
                if key in found:
                    # Canonical key spelling avoids ambiguous mixed-case switches.
                    if arg.partition('=')[0] != key:
                        raise RuntimeError('Unsafe existing Claude main process')
                    if expected[key] is None:
                        found[key].append(value if separator else None)
                    else:
                        found[key].append(value if separator else (argv[index + 1] if index + 1 < len(argv) else None))
            if any(found[key] != [value] for key, value in expected.items()):
                raise RuntimeError('Unsafe existing Claude main process')
    except RuntimeError as error:
        if str(error) == 'Unsafe existing Claude main process':
            raise RuntimeError('Claude 已在未使用完整安全代理与隐私参数的旧进程中运行。请先保存工作，从 Claude 菜单完整退出（关闭窗口可能仍驻留后台），再打开“Claude 安全联网”。不会强制结束你的进程。') from None
        raise RuntimeError('无法核实正在运行的 Claude 进程，已停止启动。请保存工作并完整退出 Claude，再打开“Claude 安全联网”。') from None
    except Exception:
        raise RuntimeError('无法核实正在运行的 Claude 进程，已停止启动。请保存工作并完整退出 Claude，再打开“Claude 安全联网”。') from None


def launch():
    if not (ROOT / 'installed.json').exists():
        raise RuntimeError('System enforcement is not installed')
    proxy = 'http://%s:%s' % LISTEN
    env = dict(os.environ)
    for key in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        env[key] = proxy
    env['NO_PROXY'] = env['no_proxy'] = ''
    config = json.loads((ROOT / 'runtime.json').read_text(encoding='utf-8'))
    # WindowsApps does not grant ordinary users directory enumeration. Query the
    # package manager instead of silently relying on glob's empty result.
    query = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                            'Get-AppxPackage -Name Claude | Sort-Object Version -Descending | Select-Object -First 1 -ExpandProperty InstallLocation'],
                           capture_output=True, text=True, timeout=10,
                           creationflags=subprocess.CREATE_NO_WINDOW)
    package_dir = Path(query.stdout.strip())
    app_dir = Path(config['package_parent'])
    candidate = package_dir / 'app' / 'Claude.exe'
    installed = json.loads((ROOT / 'installed.json').read_text(encoding='utf-8-sig'))
    if (query.returncode != 0 or package_dir.parent != app_dir or
            package_dir.name != installed.get('package') or not candidate.is_file()):
        raise RuntimeError('Claude 已更新或安装路径变化，请重新应用网络保护后再启动。')
    existing_claude_launch_preflight(candidate)
    subprocess.Popen(claude_launch_arguments(candidate), env=env,
                     creationflags=subprocess.CREATE_NO_WINDOW)


def start_hidden():
    pythonw = Path(sys.executable).with_name('pythonw.exe')
    if not pythonw.exists():
        raise RuntimeError('Python windowless runtime missing')
    subprocess.Popen([str(pythonw), str(Path(__file__).resolve()), '--serve'],
                     creationflags=subprocess.CREATE_NO_WINDOW)


def message(text):
    ctypes.windll.user32.MessageBoxW(None, text, 'Claude 安全联网', 0x10)


def verified_gate_for_launch():
    if not (ROOT / 'installed.json').exists():
        raise RuntimeError('System enforcement is not installed')
    # A fresh network check is required: a stale status.json is never authority.
    actual = verify_exit_sync()
    with socket.create_connection(LISTEN, timeout=1):
        pass
    if actual not in configured_allowlist() or (ROOT / 'hold.block').exists():
        raise RuntimeError('Exit not allowed by the current policy')
    return actual


if __name__ == '__main__':
    try:
        if '--serve' in sys.argv:
            asyncio.run(serve())
        elif '--launch' in sys.argv:
            if not (ROOT / 'installed.json').exists():
                raise RuntimeError('System enforcement is not installed')
            try:
                with socket.create_connection(LISTEN, timeout=1):
                    pass
            except OSError:
                start_hidden()
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    verified_gate_for_launch()
                    break
                except (OSError, ValueError, RuntimeError):
                    pass
                time.sleep(.25)
            else:
                raise RuntimeError('出口 IP 未通过校验，Claude 保持断网。请先确认家宽连接正常。')
            launch()
        else:
            raise RuntimeError('Use --serve or --launch')
    except Exception as e:
        if '--serve' not in sys.argv:
            message(str(e))
        sys.exit(1)
