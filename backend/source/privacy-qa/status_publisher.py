"""Private-stdio status publisher for its one owning Node controller.

The destination is derived from the verified parent PID. No path, command or
network operation is accepted through stdin. All writes use the shared Windows
atomic JSON implementation and its per-path interprocess serialization.
"""
from pathlib import Path
import argparse
import json
import os
import sys
import time
import re

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
import environment_lease as leases

MAX_FRAME=32768
FIELDS=frozenset(('schema_version','kind','process_pid','version','status','activation_attempted',
                 'activation_complete','protected_environment_verified','network_hold_managed_by_caller',
                 'environment_check_at','environment_check_ok','environment_check_pending','navigation_guard','navigation_completions','last_environment_diagnostic','counts',
                 'limits','environment_scope','profile_scope','at','error_codes','document_health','qa_diagnostic','topology_diagnostic','configuration_generation','worker_navigation_evidence','loading_diagnostic','unpaused_retirement_evidence','activation_navigation_diagnostic','activation_diagnostic','target_type_diagnostic','target_lifecycle_diagnostic','verified_scope_navigation_evidence','autoattach_pending_diagnostic','suspension_guard'))

NATIVE_FIELDS=frozenset(('schema_version','kind','process_pid','version','status','verification_mode','environment_scope','profile_scope',
    'activation_attempted','activation_complete','protected_environment_verified','network_hold_managed_by_caller',
    'environment_check_at','environment_check_ok','environment_check_pending','startup_runtime_checked_at','startup_runtime',
    'controller_heartbeat_checked_at','last_environment_diagnostic','counts','limits','at','error_codes','native_activation',
    'native_runtime_observation','native_qa_diagnostic','native_loading_diagnostic','activation_navigation_diagnostic'))
NATIVE_REQUIRED=NATIVE_FIELDS-{'native_runtime_observation','native_qa_diagnostic','native_loading_diagnostic','activation_navigation_diagnostic'}
NATIVE_COUNTS=frozenset(('attached','metadata_matches','metadata_mismatches','command_errors','startup_checks','passive_checks','passive_unobserved'))
NATIVE_STATES=frozenset(('starting','monitoring','environment_failed','stopping','stopped','child_exited','child_shutdown_not_confirmed'))
NATIVE_ERRORS=frozenset(('controller_start_failed','lifecycle_marker_failed','private_pipe_unavailable','publisher_unavailable',
    'startup_runtime_not_verified','runtime_mismatch','controller_failed','graceful_child_close_not_confirmed'))
NATIVE_REASONS=frozenset(('none','cdp_command_timeout','cdp_command_rejected','target_unavailable','inventory_unavailable','invalid_result',
    'timezone_mismatch','locale_mismatch','language_mismatch','daylight_offset_mismatch','rtc_raw_address_observed','rtc_not_completed','private_pipe_unavailable'))

RTC_KEYS=frozenset(('total','privateIPv4','linkLocalIPv4','loopbackIPv4','publicIPv4','ulaIPv6','linkLocalIPv6','loopbackIPv6','globalIPv6','unspecifiedIPv4','unspecifiedIPv6','mdns','noAddress','otherAddress','host','srflx','prflx','relay','unknownType'))
HEALTH_KEYS=frozenset(('isErrorDocument','securityOriginMatchesProtected','protectedHttpsDocument','unreachableDocument'))
RAW_KEYS=frozenset(('privateIPv4','linkLocalIPv4','loopbackIPv4','publicIPv4','ulaIPv6','linkLocalIPv6','loopbackIPv6','globalIPv6','otherAddress'))

def _exact(value,keys):
    return isinstance(value,dict) and set(value)==set(keys)

def _timestamp(value):
    import datetime
    if not isinstance(value,str) or len(value)!=24 or not value.endswith('Z'):return False
    try:return datetime.datetime.fromisoformat(value[:-1]+'+00:00').isoformat(timespec='milliseconds').replace('+00:00','Z')==value
    except ValueError:return False

def _health(value):
    return all(value.get(k) is None or type(value[k]) is bool for k in HEALTH_KEYS) and HEALTH_KEYS.issubset(value)

def _rtc(value):
    if not _exact(value,('status','gatheringComplete','statsAvailable','events','sdp','stats')):return False
    if value['status'] not in ('api_unavailable','complete','timed_out','probe_failed') or type(value['gatheringComplete']) is not bool or type(value['statsAvailable']) is not bool:return False
    for source in ('events','sdp','stats'):
        if not _exact(value[source],RTC_KEYS) or any(type(n) is not int or not 0<=n<=2048 for n in value[source].values()):return False
        c=value[source]
        if c['total']!=sum(c[k] for k in ('host','srflx','prflx','relay','unknownType')) or c['total']!=sum(c[k] for k in RTC_KEYS-{'total','host','srflx','prflx','relay','unknownType'}):return False
    return True

def validate_document_diagnostics(value):
    if 'document_health' in value:
        item=value['document_health']
        if (not _exact(item,('schema','scope','checked_at','accepted','pages')) or type(item['schema']) is not int or item['schema']!=1
                or item['scope']!='activation-top-level-committed-documents-v1' or not _timestamp(item['checked_at']) or type(item['accepted']) is not bool
                or not isinstance(item['pages'],list) or len(item['pages'])>16):raise leases.LeaseError('publisher_document_health_invalid')
        for page in item['pages']:
            if not _exact(page,HEALTH_KEYS|{'freshDocument'}) or not _health(page) or type(page['freshDocument']) is not bool:raise leases.LeaseError('publisher_document_health_invalid')
        if item['accepted'] and (not item['pages'] or not all(p['isErrorDocument'] is False and p['securityOriginMatchesProtected'] is True and p['protectedHttpsDocument'] is True and p['unreachableDocument'] is False and p['freshDocument'] is True for p in item['pages'])):raise leases.LeaseError('publisher_document_health_invalid')
    if 'qa_diagnostic' in value:
        item=value['qa_diagnostic']
        if (not _exact(item,('schema','scope','checked_at','complete_target_inventory','accepted','pages')) or type(item['schema']) is not int or item['schema']!=1
                or item['scope']!='fixed-top-level-document-and-no-stun-rtc-v1' or not _timestamp(item['checked_at'])
                or type(item['accepted']) is not bool or type(item['complete_target_inventory']) is not bool
                or not isinstance(item['pages'],list) or len(item['pages'])>16):raise leases.LeaseError('publisher_qa_diagnostic_invalid')
        pagekeys=HEALTH_KEYS|{'mainDocumentLoaded','environmentMatches','rtc','rtcNoRawAddressObserved','rtcAccepted','accepted'}
        for page in item['pages']:
            if (not _exact(page,pagekeys) or not _health(page)
                    or any(type(page[k]) is not bool for k in ('mainDocumentLoaded','environmentMatches','rtcNoRawAddressObserved','rtcAccepted','accepted'))
                    or (page['rtc'] is not None and not _rtc(page['rtc']))):raise leases.LeaseError('publisher_qa_diagnostic_invalid')
            rtc=page['rtc']
            no_raw=rtc is not None and all(rtc[source][key]==0 for source in ('events','sdp','stats') for key in RAW_KEYS)
            unavailable=rtc is not None and rtc['status']=='api_unavailable' and not rtc['gatheringComplete'] and not rtc['statsAvailable'] and all(n==0 for source in ('events','sdp','stats') for n in rtc[source].values())
            rtc_ok=rtc is not None and (unavailable or (rtc['status']=='complete' and rtc['gatheringComplete'] and rtc['statsAvailable'] and no_raw))
            accepted=(page['isErrorDocument'] is False and page['securityOriginMatchesProtected'] is True and page['protectedHttpsDocument'] is True and page['unreachableDocument'] is False and page['mainDocumentLoaded'] and page['environmentMatches'] and rtc_ok)
            if page['rtcNoRawAddressObserved']!=no_raw or page['rtcAccepted']!=rtc_ok or page['accepted']!=accepted:raise leases.LeaseError('publisher_qa_diagnostic_invalid')
        if item['accepted']!=(item['complete_target_inventory'] and bool(item['pages']) and all(p['accepted'] for p in item['pages'])):raise leases.LeaseError('publisher_qa_diagnostic_invalid')


TOPOLOGY_EVENTS=frozenset(('diagnostic_enabled','target_created_observed','target_destroyed_observed','auto_attach_observed','detach_observed','navigation_invalidated','manual_attach_requested','record_attach','existing_session_ignored','existing_session_checked','auto_attach_pending','auto_attach_resumed','alias_binding_verified','configuration_started','configuration_applied','sweep_scope_pending','retired_duplicate_ignored','retired_setup_target'))
TOPOLOGY_TYPES=frozenset(('page','iframe','worker','service_worker','shared_worker','browser','tab','other'))
TOPOLOGY_DETAILS=frozenset(('none','scope_changed','private_pipe_unavailable','navigation_deadline_expired','navigation_binding_unavailable','configuration_changed','other','worker','page','unknown_inventory','not_checked_or_configured','setup_target_absent'))

def validate_topology_diagnostic(value):
    if 'topology_diagnostic' not in value:return
    import re,datetime
    item=value['topology_diagnostic']
    if (not _exact(item,('schema','scope','checked_at','expires_at','events')) or type(item['schema']) is not int or item['schema']!=1
            or item['scope']!='bounded-target-topology-v1' or not _timestamp(item['checked_at']) or not _timestamp(item['expires_at'])
            or not isinstance(item['events'],list) or not 1<=len(item['events'])<=64):raise leases.LeaseError('publisher_topology_invalid')
    check=datetime.datetime.fromisoformat(item['checked_at'][:-1]+'+00:00');expiry=datetime.datetime.fromisoformat(item['expires_at'][:-1]+'+00:00')
    if not 0<=(expiry-check).total_seconds()<=60:raise leases.LeaseError('publisher_topology_invalid')
    last_seq=0;last_elapsed=-1
    for e in item['events']:
        if (not _exact(e,('seq','elapsed_ms','event','type','target_hash','session_hash','paused','source','detail','duplicate_target'))
                or type(e['seq']) is not int or not last_seq<e['seq']<=9007199254740991
                or type(e['elapsed_ms']) is not int or not last_elapsed<=e['elapsed_ms']<=86400000
                or e['event'] not in TOPOLOGY_EVENTS or e['type'] not in TOPOLOGY_TYPES
                or e['source'] not in ('none','auto_event','manual_reconcile','direct') or e['detail'] not in TOPOLOGY_DETAILS
                or any(e[k] is not None and (type(e[k]) is not str or not re.fullmatch('[a-f0-9]{16}',e[k])) for k in ('target_hash','session_hash'))
                or e['paused'] is not None and type(e['paused']) is not bool or type(e['duplicate_target']) is not bool):raise leases.LeaseError('publisher_topology_invalid')
        last_seq=e['seq'];last_elapsed=e['elapsed_ms']



WORKER_NAVIGATION_FIELDS=frozenset(('schema','mode','navigation_started_at','navigation_checked_at',
    'navigation_deadline_at','first_runtime_checked_at','configuration_generation','worker_count',
    'inherited_worker_count','min_runtime_checked_at','bindings_verified'))

def validate_worker_navigation_evidence(value):
    if 'configuration_generation' in value and (type(value['configuration_generation']) is not int
            or not 0<=value['configuration_generation']<=9007199254740991):
        raise leases.LeaseError('publisher_worker_evidence_invalid')
    if 'worker_navigation_evidence' not in value:return
    import datetime
    item=value['worker_navigation_evidence'];nav=value.get('navigation_guard');counts=value.get('counts',{})
    if (not _exact(item,WORKER_NAVIGATION_FIELDS) or type(nav) is not dict
            or type(item.get('schema')) is not int or item['schema']!=1
            or item.get('mode')!='fresh_worker_runtime_same_navigation' or item.get('bindings_verified') is not True
            or type(value.get('configuration_generation')) is not int or not 1<=value['configuration_generation']<=9007199254740991
            or type(item.get('configuration_generation')) is not int or item['configuration_generation']!=value['configuration_generation']
            or type(item.get('worker_count')) is not int or not 1<=item['worker_count']<=64
            or type(item.get('inherited_worker_count')) is not int or not 1<=item['inherited_worker_count']<=item['worker_count']
            or type(counts) is not dict or type(counts.get('workers_inherited_verified')) is not int
            or counts['workers_inherited_verified']<item['inherited_worker_count']):raise leases.LeaseError('publisher_worker_evidence_invalid')
    mapping=(('navigation_started_at','started_at'),('navigation_checked_at','checked_at'),
             ('navigation_deadline_at','deadline_at'),('first_runtime_checked_at','first_runtime_checked_at'))
    for field,nav_field in mapping:
        if not _timestamp(item[field]) or item[field]!=nav.get(nav_field):raise leases.LeaseError('publisher_worker_evidence_invalid')
    if not _timestamp(item['min_runtime_checked_at']) or not _timestamp(value.get('at')):raise leases.LeaseError('publisher_worker_evidence_invalid')
    parse=lambda x:datetime.datetime.fromisoformat(x[:-1]+'+00:00')
    started,checked,deadline,first,minimum=(parse(item[k]) for k in ('navigation_started_at','navigation_checked_at','navigation_deadline_at','first_runtime_checked_at','min_runtime_checked_at'))
    observed=parse(value['at'])
    if (not first<=started<=checked<=deadline or not 0<=(deadline-started).total_seconds()<=15
            or not 0<=(started-first).total_seconds()<=4 or not 0<=(observed-minimum).total_seconds()<=4):
        raise leases.LeaseError('publisher_worker_evidence_invalid')



UNPAUSED_RETIREMENT_FIELDS=frozenset(('schema','mode','checked_at',
    'configuration_generation','early_unpaused_total','retired_unpaused_verified',
    'live_unpaused_count','inventory_complete','navigation_started_at','navigation_checked_at'))


def validate_unpaused_retirement_evidence(value):
    if 'unpaused_retirement_evidence' not in value:return
    import datetime
    item=value['unpaused_retirement_evidence'];nav=value.get('navigation_guard');counts=value.get('counts',{})
    if (not _exact(item,UNPAUSED_RETIREMENT_FIELDS) or type(nav) is not dict
            or type(item.get('schema')) is not int or item['schema']!=1
            or item.get('mode')!='retired_unpaused_absent_from_root_inventory'
            or item.get('inventory_complete') is not True
            or type(value.get('configuration_generation')) is not int
            or not 1<=value['configuration_generation']<=9007199254740991
            or type(item.get('configuration_generation')) is not int
            or item['configuration_generation']!=value['configuration_generation']):
        raise leases.LeaseError('publisher_unpaused_retirement_invalid')
    total,retired,live=(item.get(k) for k in ('early_unpaused_total','retired_unpaused_verified','live_unpaused_count'))
    if (type(total) is not int or not 2<=total<=4096
            or type(retired) is not int or not 1<=retired<=total
            or type(live) is not int or live not in (0,1) or total!=retired+live
            or type(counts) is not dict or type(counts.get('early_unpaused_targets')) is not int
            or counts['early_unpaused_targets']!=total
            or type(counts.get('unpaused_retired_verified')) is not int
            or counts['unpaused_retired_verified']!=retired):
        raise leases.LeaseError('publisher_unpaused_retirement_invalid')
    for field,nav_field in (('navigation_started_at','started_at'),('navigation_checked_at','checked_at')):
        if not _timestamp(item[field]) or item[field]!=nav.get(nav_field):
            raise leases.LeaseError('publisher_unpaused_retirement_invalid')
    if (not _timestamp(item['checked_at']) or item['checked_at']!=item['navigation_checked_at']
            or not _timestamp(value.get('at'))):
        raise leases.LeaseError('publisher_unpaused_retirement_invalid')
    parse=lambda x:datetime.datetime.fromisoformat(x[:-1]+'+00:00')
    started,checked,observed=(parse(item['navigation_started_at']),parse(item['checked_at']),parse(value['at']))
    if not started<=checked<=observed or not 0<=(observed-checked).total_seconds()<=4:
        raise leases.LeaseError('publisher_unpaused_retirement_invalid')


LOADING_RESOURCE_KEYS=frozenset(('script','css','img','fetch','xmlhttprequest','link','iframe','other'))
LOADING_STATUS_KEYS=frozenset(('success','redirect','clientError','serverError','unknown'))
LOADING_TIME_KEYS=frozenset(('documentAgeMs','domInteractiveMs','domContentLoadedMs','loadEventEndMs'))

def validate_loading_diagnostic(value):
    if 'loading_diagnostic' not in value:return
    item=value['loading_diagnostic']
    if (not _exact(item,('schema','scope','checked_at','complete_target_inventory','pages'))
            or type(item['schema']) is not int or item['schema']!=1
            or item['scope']!='fixed-top-level-loading-state-v1' or not _timestamp(item['checked_at'])
            or type(item['complete_target_inventory']) is not bool or type(item['pages']) is not list or len(item['pages'])>16):
        raise leases.LeaseError('publisher_loading_diagnostic_invalid')
    pagekeys=HEALTH_KEYS|LOADING_TIME_KEYS|{'readyState','performanceAvailable','resourceCounts','responseStatusCounts'}
    for page in item['pages']:
        if (not _exact(page,pagekeys) or not _health(page) or page['readyState'] not in ('loading','interactive','complete','unavailable')
                or type(page['performanceAvailable']) is not bool
                or any(page[k] is not None and (type(page[k]) is not int or not 0<=page[k]<=604800000) for k in LOADING_TIME_KEYS)
                or not _exact(page['resourceCounts'],LOADING_RESOURCE_KEYS) or not _exact(page['responseStatusCounts'],LOADING_STATUS_KEYS)
                or any(type(n) is not int or not 0<=n<=8192 for n in (*page['resourceCounts'].values(),*page['responseStatusCounts'].values()))):
            raise leases.LeaseError('publisher_loading_diagnostic_invalid')
        resources=sum(page['resourceCounts'].values());statuses=sum(page['responseStatusCounts'].values())
        if (resources>8192 or resources!=statuses or (not page['performanceAvailable'] and
                (resources!=0 or any(page[k] is not None for k in LOADING_TIME_KEYS)))
                or (page['performanceAvailable'] and page['documentAgeMs'] is None)):
            raise leases.LeaseError('publisher_loading_diagnostic_invalid')

STARTUP_NAVIGATION_CODES=frozenset(('ok','invalid_result','download_disallowed','net_proxy_connection_failed','net_tunnel_connection_failed','net_network_changed','net_connection_reset','net_connection_closed','net_connection_timed_out','net_timed_out','net_name_not_resolved','net_aborted','net_tls_or_certificate_error','net_access_denied','net_blocked','net_other_error'))

def validate_startup_navigation_diagnostic(value):
    if 'activation_navigation_diagnostic' not in value:return
    item=value['activation_navigation_diagnostic']
    if (not _exact(item,('schema','scope','checked_at','results')) or type(item['schema']) is not int or item['schema']!=1
            or item['scope']!='fixed-startup-navigation-results-v1' or not _timestamp(item['checked_at'])
            or type(item['results']) is not list or not 1<=len(item['results'])<=32):
        raise leases.LeaseError('publisher_startup_navigation_invalid')
    for result in item['results']:
        if (not _exact(result,('operation','attempt','code')) or type(result['operation']) is not str or result['operation'] not in ('navigate','reload')
                or type(result['attempt']) is not int or result['attempt'] not in (1,2)
                or type(result['code']) is not str or result['code'] not in STARTUP_NAVIGATION_CODES):
            raise leases.LeaseError('publisher_startup_navigation_invalid')


ACTIVATION_STAGES=frozenset(('candidates','classify_url','before_document','navigation_command','document_observation','metadata_check','environment_check','complete'))
ACTIVATION_CODES=frozenset(('started','skipped_url','no_candidates','ok','cdp_command_timeout','cdp_command_rejected','private_pipe_closed','private_pipe_write_failed','identity_changed','budget_expired','document_not_accepted','metadata_not_verified','environment_not_verified','other_error'))
ACTIVATION_URL_CLASSES=frozenset(('blank','protected_https','unprotected_web','local','other','unavailable'))

def validate_activation_diagnostic(value):
    if 'activation_diagnostic' not in value:return
    item=value['activation_diagnostic']
    if (not _exact(item,('schema','scope','checked_at','events')) or type(item['schema']) is not int or item['schema']!=1
            or item['scope']!='fixed-activation-steps-v1' or not _timestamp(item['checked_at'])
            or type(item['events']) is not list or not 1<=len(item['events'])<=32):
        raise leases.LeaseError('publisher_activation_invalid')
    for event in item['events']:
        if (not _exact(event,('stage','code','url_class'))
                or type(event['stage']) is not str or event['stage'] not in ACTIVATION_STAGES
                or type(event['code']) is not str or event['code'] not in ACTIVATION_CODES
                or type(event['url_class']) is not str or event['url_class'] not in ACTIVATION_URL_CLASSES):
            raise leases.LeaseError('publisher_activation_invalid')


TARGET_TYPE_LABELS=frozenset(('page','iframe','worker','service_worker','shared_worker','other','tab','browser','unknown'))
TARGET_TYPE_EVENTS=frozenset(('type_change_seen','inventory_mismatch','promotion_started','promotion_verified','type_refused','stale_result_discarded','retired'))
TARGET_TYPE_SOURCES=frozenset(('target_info_event','reconcile','sweep','configuration','metadata'))
def validate_target_type_diagnostic(value):
    if 'target_type_diagnostic' not in value:return
    item=value['target_type_diagnostic']
    if (not _exact(item,('schema','scope','checked_at','events')) or type(item['schema']) is not int or item['schema']!=1
            or item['scope']!='fixed-target-type-reconciliation-v1' or not _timestamp(item['checked_at'])
            or type(item['events']) is not list or not 1<=len(item['events'])<=32):
        raise leases.LeaseError('publisher_target_type_invalid')
    import re
    for e in item['events']:
        if (not _exact(e,('event','source','cached_type','current_type','target_hash','session_hash'))
                or type(e['event']) is not str or e['event'] not in TARGET_TYPE_EVENTS
                or type(e['source']) is not str or e['source'] not in TARGET_TYPE_SOURCES
                or type(e['cached_type']) is not str or e['cached_type'] not in TARGET_TYPE_LABELS
                or type(e['current_type']) is not str or e['current_type'] not in TARGET_TYPE_LABELS
                or any(e[k] is not None and (type(e[k]) is not str or not re.fullmatch('[a-f0-9]{16}',e[k])) for k in ('target_hash','session_hash'))):
            raise leases.LeaseError('publisher_target_type_invalid')

TARGET_LIFECYCLE_EVENTS=frozenset(('operation_failed','retirement_verified','retirement_refused','resume_verified'))
TARGET_LIFECYCLE_SOURCES=frozenset(('setup','resume','metadata','alias'))
TARGET_LIFECYCLE_REASONS=frozenset(('none','target_present','identity_changed','inventory_unavailable','inventory_invalid','cdp_command_timeout','cdp_command_rejected','private_pipe_closed','private_pipe_write_failed','other_error'))
def validate_target_lifecycle_diagnostic(value):
    if 'target_lifecycle_diagnostic' not in value:return
    item=value['target_lifecycle_diagnostic']
    if (not _exact(item,('schema','scope','checked_at','events')) or type(item['schema']) is not int or item['schema']!=1
            or item['scope']!='fixed-target-lifecycle-v1' or not _timestamp(item['checked_at'])
            or type(item['events']) is not list or not 1<=len(item['events'])<=8):
        raise leases.LeaseError('publisher_target_lifecycle_invalid')
    import re
    for e in item['events']:
        if (not _exact(e,('event','source','reason','type','target_hash','session_hash'))
                or type(e['event']) is not str or e['event'] not in TARGET_LIFECYCLE_EVENTS
                or type(e['source']) is not str or e['source'] not in TARGET_LIFECYCLE_SOURCES
                or type(e['reason']) is not str or e['reason'] not in TARGET_LIFECYCLE_REASONS
                or type(e['type']) is not str or e['type'] not in TARGET_TYPE_LABELS
                or any(e[k] is not None and (type(e[k]) is not str or not re.fullmatch('[a-f0-9]{16}',e[k])) for k in ('target_hash','session_hash'))):
            raise leases.LeaseError('publisher_target_lifecycle_invalid')

VERIFIED_SCOPE_NAVIGATION_FIELDS=frozenset(('schema','mode','checked_at','configuration_generation','scope_target_count',
    'previously_verified_target_count','early_unpaused_total','retired_unpaused_verified','live_unpaused_count',
    'inventory_complete','bindings_verified','baseline_scope_fingerprint','current_scope_fingerprint',
    'navigation_started_at','navigation_checked_at','navigation_deadline_at','first_runtime_checked_at'))
def validate_verified_scope_navigation_evidence(value):
    if 'verified_scope_navigation_evidence' not in value:return
    import re,datetime
    item=value['verified_scope_navigation_evidence'];nav=value.get('navigation_guard');counts=value.get('counts',{})
    if (not _exact(item,VERIFIED_SCOPE_NAVIGATION_FIELDS) or type(item['schema']) is not int or item['schema']!=1
            or item['mode']!='complete_verified_scope_same_navigation_v1' or type(nav) is not dict
            or item['inventory_complete'] is not True or item['bindings_verified'] is not True
            or type(value.get('configuration_generation')) is not int or not 1<=value['configuration_generation']<=9007199254740991
            or type(item['configuration_generation']) is not int or item['configuration_generation']!=value['configuration_generation']):
        raise leases.LeaseError('publisher_verified_scope_evidence_invalid')
    target_count,previous,total,retired,live=(item[k] for k in ('scope_target_count','previously_verified_target_count','early_unpaused_total','retired_unpaused_verified','live_unpaused_count'))
    if (any(type(n) is not int for n in (target_count,previous,total,retired,live))
            or not 1<=target_count<=4096 or target_count!=previous or not 1<=total<=4096
            or not 0<=retired<=total or not 0<=live<=target_count or total!=retired+live
            or type(counts) is not dict or type(counts.get('early_unpaused_targets')) is not int or counts['early_unpaused_targets']!=total
            or type(counts.get('unpaused_retired_verified')) is not int or counts['unpaused_retired_verified']!=retired
            or any(type(item[k]) is not str or not re.fullmatch('[a-f0-9]{64}',item[k]) for k in ('baseline_scope_fingerprint','current_scope_fingerprint'))
            or item['baseline_scope_fingerprint']!=item['current_scope_fingerprint']):
        raise leases.LeaseError('publisher_verified_scope_evidence_invalid')
    for field,nav_field in (('navigation_started_at','started_at'),('navigation_checked_at','checked_at'),('navigation_deadline_at','deadline_at'),('first_runtime_checked_at','first_runtime_checked_at')):
        if not _timestamp(item[field]) or item[field]!=nav.get(nav_field):raise leases.LeaseError('publisher_verified_scope_evidence_invalid')
    if not _timestamp(item['checked_at']) or item['checked_at']!=item['navigation_checked_at']:raise leases.LeaseError('publisher_verified_scope_evidence_invalid')
    stamp=lambda k:datetime.datetime.fromisoformat(item[k][:-1]+'+00:00')
    baseline,started,checked,deadline=(stamp(k) for k in ('first_runtime_checked_at','navigation_started_at','navigation_checked_at','navigation_deadline_at'))
    if not baseline<=started<=checked<=deadline or not 0<=(started-baseline).total_seconds()<=4 or not 0<(deadline-started).total_seconds()<=15:
        raise leases.LeaseError('publisher_verified_scope_evidence_invalid')

def validate_autoattach_pending_diagnostic(value):
    if 'autoattach_pending_diagnostic' not in value:return
    import re
    item=value['autoattach_pending_diagnostic']
    if (not _exact(item,('schema','scope','checked_at','events')) or type(item['schema']) is not int or item['schema']!=1
            or item['scope']!='fixed-autoattach-pending-v1' or not _timestamp(item['checked_at'])
            or not isinstance(item['events'],list) or not 1<=len(item['events'])<=16):
        raise leases.LeaseError('publisher_autoattach_pending_invalid')
    fields=('event','reason','type','target_hash','age_bucket','canonical_count','alias_count','waiting_count','pending_count',
            'previous_session_hash','replacement_session_hash','unpaused_history_count','retired_history_count','rebind_count')
    reasons=('none','target_absent','owned_canonical','unpaused_canonical','no_eligible_alias','identity_changed','inventory_not_exact','runtime_unavailable','runtime_mismatch','setup_failed','scope_transition_retry_pending','retry_budget_expired')
    for event in item['events']:
        if (not _exact(event,fields) or event['event'] not in ('pending','resolved','timeout','canonical_detached','alias_promoted','alias_refused')
                or event['reason'] not in reasons or event['type'] not in TOPOLOGY_TYPES|{'unknown'}
                or any(event[k] is not None and (type(event[k]) is not str or not re.fullmatch('[a-f0-9]{16}',event[k]))
                       for k in ('target_hash','previous_session_hash','replacement_session_hash'))
                or event['age_bucket'] not in ('under_1s','1_to_4s','4_to_5s','at_least_5s')
                or any(type(event[k]) is not int or not 0<=event[k]<=limit for k,limit in
                       (('canonical_count',1),('alias_count',64),('waiting_count',4096),('pending_count',64),
                        ('unpaused_history_count',4096),('retired_history_count',4096),('rebind_count',4096)))):
            raise leases.LeaseError('publisher_autoattach_pending_invalid')


SUSPENSION_GUARD_FIELDS=frozenset(('schema','mode','started_at','checked_at','deadline_at',
    'first_runtime_checked_at','configuration_generation','inventory_complete','inventory_fingerprint','target_count'))


def validate_suspension_guard(value):
    if 'suspension_guard' not in value:return
    import datetime,re
    item=value['suspension_guard'];counts=value.get('counts');codes=value.get('error_codes')
    if (not _exact(item,SUSPENSION_GUARD_FIELDS) or type(item.get('schema')) is not int or item['schema']!=1
            or item.get('mode')!='zero_byte_scope_transition' or item.get('inventory_complete') is not True
            or value.get('kind')!='browser' or value.get('activation_complete') is not True
            or value.get('environment_check_ok') is not False or value.get('environment_check_pending') is not True
            or value.get('navigation_guard') is not None
            or value.get('last_environment_diagnostic') not in ('scope_changed','configuration_changed','navigation_configuration_pending','navigation_deadline_expired','metadata_unavailable')
            or not ((value.get('status')=='monitoring' and codes==[])
                    or (value.get('status')=='partial' and codes==['early_unpaused_target']))
            or type(counts) is not dict
            or any(type(counts.get(key)) is not int or counts[key]!=0 for key in
                   ('metadata_mismatches','command_errors','workers_unverified','unprotected_targets','unknown_target_types','environment_check_failures'))
            or type(value.get('configuration_generation')) is not int
            or not 0<=value['configuration_generation']<=9007199254740991
            or type(item.get('configuration_generation')) is not int
            or not 0<=item['configuration_generation']<=value['configuration_generation']
            or type(item.get('target_count')) is not int or not 1<=item['target_count']<=4096
            or type(item.get('inventory_fingerprint')) is not str or not re.fullmatch('[a-f0-9]{64}',item['inventory_fingerprint'])
            or any(not _timestamp(item.get(key)) for key in ('started_at','checked_at','deadline_at','first_runtime_checked_at'))
            or not _timestamp(value.get('at')) or item['first_runtime_checked_at']!=value.get('environment_check_at')):
        raise leases.LeaseError('publisher_suspension_guard_invalid')
    parse=lambda x:datetime.datetime.fromisoformat(x[:-1]+'+00:00')
    started,checked,deadline,baseline,observed=(parse(x) for x in
        (item['started_at'],item['checked_at'],item['deadline_at'],item['first_runtime_checked_at'],value['at']))
    # Root liveness is independent from the old runtime baseline. It may predate
    # the pending event; it can never admit application data or retime baseline.
    if (not baseline<=started<=observed<deadline or not 0<(deadline-started).total_seconds()<=30
            or not 0<=(observed-checked).total_seconds()<4):
        raise leases.LeaseError('publisher_suspension_guard_invalid')


def validate_native_status(value):
    import datetime,re
    if (not isinstance(value,dict) or not set(value).issubset(NATIVE_FIELDS) or not NATIVE_REQUIRED.issubset(value)
            or type(value['schema_version']) is not int or value['schema_version']!=1 or value['kind']!='browser'
            or value['verification_mode']!='native_process_policy_v1' or value['environment_scope']!='native-browser-process-policy-v1'
            or value['profile_scope'] not in ('claude-persistent','qa-isolated')
            or type(value['process_pid']) is not int or value['process_pid']<=0 or value['status'] not in NATIVE_STATES
            or value['version'] is not None and (type(value['version']) is not str or not re.fullmatch(r'[A-Za-z][A-Za-z ]*/[0-9.]+',value['version']))
            or any(type(value[k]) is not bool for k in ('activation_attempted','activation_complete','protected_environment_verified','network_hold_managed_by_caller','environment_check_ok','environment_check_pending'))
            or value['protected_environment_verified'] is not False or value['network_hold_managed_by_caller'] is not True
            or value['environment_check_pending'] is not False
            or value['last_environment_diagnostic'] not in ('not_checked','native_startup_verified','runtime_mismatch','private_pipe_unavailable','timezone_mismatch','locale_mismatch','language_mismatch','daylight_offset_mismatch','rtc_not_completed')
            or not _exact(value['counts'],NATIVE_COUNTS)
            or any(type(n) is not int or not 0<=n<=9007199254740991 for n in value['counts'].values())
            or type(value['limits']) is not list or not 1<=len(value['limits'])<=8 or any(type(s) is not str or len(s)>512 for s in value['limits'])
            or type(value['error_codes']) is not list or len(value['error_codes'])>len(NATIVE_ERRORS)
            or any(type(s) is not str or s not in NATIVE_ERRORS for s in value['error_codes']) or len(set(value['error_codes']))!=len(value['error_codes'])
            or not _timestamp(value['at']) or value['controller_heartbeat_checked_at']!=value['at']):
        raise leases.LeaseError('publisher_native_status_invalid')
    startup=value['startup_runtime'];stamp=value['startup_runtime_checked_at']
    if startup is None:
        if stamp is not None or value['environment_check_at'] is not None or value['environment_check_ok'] or value['activation_complete'] or value['counts']['startup_checks']!=0:
            raise leases.LeaseError('publisher_native_startup_invalid')
    else:
        if (not _exact(startup,('schema','scope','checked_at','environment','rtc','accepted'))
                or type(startup['schema']) is not int or startup['schema']!=1 or startup['scope']!='initial-about-blank-no-stun-v1'
                or startup['accepted'] is not True or not _timestamp(stamp) or startup['checked_at']!=stamp or value['environment_check_at']!=stamp
                or value['counts']['startup_checks']!=1):raise leases.LeaseError('publisher_native_startup_invalid')
        env=startup['environment']
        if (not _exact(env,('timeZone','locale','language','languages','januaryOffset','julyOffset'))
                or env['timeZone']!='America/New_York' or env['locale'] not in ('en-US','en_US') or env['language']!='en-US'
                or type(env['languages']) is not list or env['languages']!=['en-US','en']
                or type(env['januaryOffset']) is not int or env['januaryOffset']!=300 or type(env['julyOffset']) is not int or env['julyOffset']!=240
                or not _rtc(startup['rtc'])):raise leases.LeaseError('publisher_native_startup_invalid')
        rtc=startup['rtc'];no_raw=all(rtc[source][k]==0 for source in ('events','sdp','stats') for k in RAW_KEYS)
        unavailable=rtc['status']=='api_unavailable' and not rtc['gatheringComplete'] and not rtc['statsAvailable'] and all(n==0 for source in ('events','sdp','stats') for n in rtc[source].values())
        if not (unavailable or rtc['status']=='complete' and rtc['gatheringComplete'] and rtc['statsAvailable'] and no_raw):raise leases.LeaseError('publisher_native_startup_invalid')
        parse=lambda x:datetime.datetime.fromisoformat(x[:-1]+'+00:00')
        if parse(stamp)>parse(value['at']):raise leases.LeaseError('publisher_native_startup_invalid')
    if value['environment_check_ok'] and (value['status']!='monitoring' or value['error_codes'] or value['counts']['metadata_mismatches']!=0 or value['counts']['command_errors']!=0):
        raise leases.LeaseError('publisher_native_status_invalid')
    activation=value['native_activation']
    if (not _exact(activation,('schema','scope','command_state','checked_at')) or type(activation['schema']) is not int or activation['schema']!=1
            or activation['scope']!='fixed-protected-navigation-v1' or activation['command_state'] not in ('not_requested','in_flight','accepted','unobserved','failed')
            or (activation['checked_at'] is not None and not _timestamp(activation['checked_at']))
            or (activation['command_state']=='not_requested')!=(activation['checked_at'] is None)
            or value['activation_complete'] and (startup is None or not value['activation_attempted'])
            or activation['command_state'] in ('in_flight','accepted','unobserved') and not value['activation_complete']):
        raise leases.LeaseError('publisher_native_activation_invalid')
    if 'native_runtime_observation' in value:
        item=value['native_runtime_observation']
        if (not _exact(item,('schema','scope','checked_at','state','reason','target_type')) or type(item['schema']) is not int or item['schema']!=1
                or item['scope']!='bounded-native-runtime-observation-v1' or not _timestamp(item['checked_at'])
                or item['state'] not in ('matched','mismatch','unobserved') or item['reason'] not in NATIVE_REASONS
                or item['target_type'] not in ('page','iframe','worker','service_worker','shared_worker','other')
                or item['state']=='matched' and item['reason']!='none'
                or item['state']=='mismatch' and (value['counts']['metadata_mismatches']<1 or value['environment_check_ok'])):
            raise leases.LeaseError('publisher_native_observation_invalid')
    if 'native_qa_diagnostic' in value:
        item=value['native_qa_diagnostic']
        if (not _exact(item,('schema','scope','checked_at','observed_targets','matched_targets','unobserved_targets','rtc_accepted','main_document_loaded'))
                or type(item['schema']) is not int or item['schema']!=1 or item['scope']!='passive-fixed-native-metadata-no-stun-v1' or not _timestamp(item['checked_at'])
                or any(type(item[k]) is not int or not 0<=item[k]<=8 for k in ('observed_targets','matched_targets'))
                or type(item['unobserved_targets']) is not int or not 0<=item['unobserved_targets']<=9
                or item['matched_targets']>item['observed_targets']
                or any(item[k] is not None and type(item[k]) is not bool for k in ('rtc_accepted','main_document_loaded'))):
            raise leases.LeaseError('publisher_native_qa_invalid')
    if 'native_loading_diagnostic' in value:
        item=value['native_loading_diagnostic']
        if (not _exact(item,('schema','scope','checked_at','pages')) or type(item['schema']) is not int or item['schema']!=1
                or item['scope']!='passive-native-loading-v1' or not _timestamp(item['checked_at'])
                or type(item['pages']) is not list or len(item['pages'])>8):raise leases.LeaseError('publisher_native_loading_invalid')
        pagekeys=(HEALTH_KEYS-{'unreachableDocument'})|LOADING_TIME_KEYS|{'state','readyState','performanceAvailable','resourceCounts','responseStatusCounts'}
        for page in item['pages']:
            if _exact(page,('state',)) and page['state']=='unobserved':continue
            if not _exact(page,pagekeys) or page['state']!='observed':raise leases.LeaseError('publisher_native_loading_invalid')
            translated={k:v for k,v in page.items() if k!='state'};translated['unreachableDocument']=None
            validate_loading_diagnostic({'loading_diagnostic':{'schema':1,'scope':'fixed-top-level-loading-state-v1','checked_at':item['checked_at'],'complete_target_inventory':False,'pages':[translated]}})
    validate_startup_navigation_diagnostic(value)
    return value


def validate_status(value):
    if isinstance(value,dict) and ('verification_mode' in value or value.get('environment_scope')=='native-browser-process-policy-v1'):
        return validate_native_status(value)
    if (not isinstance(value,dict) or not set(value).issubset(FIELDS)
            or type(value.get('schema_version')) is not int or value['schema_version']!=1
            or value.get('kind')!='browser'
            or value.get('environment_scope')!='isolated-browser-all-web-targets-v1'
            or value.get('profile_scope') not in ('claude-persistent','qa-isolated')
            or type(value.get('process_pid')) is not int or value['process_pid']<=0
            or type(value.get('environment_check_ok')) is not bool
            or ('environment_check_pending' in value and type(value['environment_check_pending']) is not bool)
            or ('navigation_completions' in value and (not isinstance(value['navigation_completions'],list) or len(value['navigation_completions'])>16))
            or not isinstance(value.get('counts'),dict)
            or not isinstance(value.get('error_codes'),list)):
        raise leases.LeaseError('publisher_status_invalid')
    validate_document_diagnostics(value)
    validate_startup_navigation_diagnostic(value)
    validate_activation_diagnostic(value)
    validate_target_type_diagnostic(value)
    validate_target_lifecycle_diagnostic(value)
    validate_autoattach_pending_diagnostic(value)
    validate_suspension_guard(value)
    validate_verified_scope_navigation_evidence(value)
    validate_loading_diagnostic(value)
    validate_topology_diagnostic(value)
    validate_worker_navigation_evidence(value)
    validate_unpaused_retirement_evidence(value)
    return value


def unique_object(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise leases.LeaseError('publisher_duplicate_key')
        value[key]=item
    return value


def frame(raw,expected):
    if not isinstance(raw,bytes) or len(raw)>MAX_FRAME or not raw.endswith(b'\n'):
        raise leases.LeaseError('publisher_frame_invalid')
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=unique_object)
    if (not isinstance(value,dict) or set(value)!= {'id','status'}
            or type(value.get('id')) is not int or value['id']!=expected):
        raise leases.LeaseError('publisher_sequence_invalid')
    return value['id'],validate_status(value['status'])


def emit(value):
    sys.stdout.buffer.write(json.dumps(value,separators=(',',':')).encode('ascii')+b'\n')
    sys.stdout.buffer.flush()


# A transient source-file mutex contention is not a changed browser policy.
# Retry only the already-validated immutable frame, without changing its `at`.
PUBLISHER_IO_RETRY_SECONDS = 1.0
PUBLISHER_IO_RETRY_GAP_SECONDS = .025
RETRYABLE_ATOMIC_CODES = frozenset(('lease_io_lock_timeout', 'lease_record_sharing_violation'))
FAILURE_CODES = frozenset(('publisher_activation_invalid','publisher_autoattach_pending_invalid',
    'publisher_document_health_invalid','publisher_duplicate_key','publisher_failed',
    'publisher_frame_invalid','publisher_loading_diagnostic_invalid','publisher_native_activation_invalid',
    'publisher_native_loading_invalid','publisher_native_observation_invalid','publisher_native_qa_invalid',
    'publisher_native_startup_invalid','publisher_native_status_invalid','publisher_parent_exited',
    'publisher_parent_invalid','publisher_qa_diagnostic_invalid','publisher_sequence_invalid',
    'publisher_startup_navigation_invalid','publisher_status_invalid','publisher_suspension_guard_invalid',
    'publisher_target_lifecycle_invalid','publisher_target_type_invalid','publisher_topology_invalid',
    'publisher_unpaused_retirement_invalid','publisher_verified_scope_evidence_invalid',
    'publisher_worker_evidence_invalid','publisher_atomic_retry_budget_expired','publisher_monotonic_invalid',
    'lease_io_lock_timeout','lease_record_sharing_violation','lease_path_invalid',
    'lease_record_too_large','lease_atomic_replace_unavailable','lease_io_lock_unavailable',
    'lease_io_lock_release_failed','process_identity_unavailable','lease_record_access_denied'))
_failure_binding = None
_last_retry_count = 0


def safe_failure_code(error):
    return str(error) if isinstance(error,leases.LeaseError) and str(error) in FAILURE_CODES else 'publisher_failed'


def write_validated_status(owner,destination,value):
    """Bound retries only; neither schema nor process failures are retried.

    An OS file operation itself cannot be preempted by this helper. A result
    returning after the one-second budget is not ACKed. The old frame times are
    retained even when a retry succeeds, and the guard retains its own 4s TTL.
    """
    global _last_retry_count
    _last_retry_count=0
    began=time.monotonic()
    while True:
        if not leases.alive(owner):raise leases.LeaseError('publisher_parent_exited')
        elapsed=time.monotonic()-began
        if elapsed<0:raise leases.LeaseError('publisher_monotonic_invalid')
        if not elapsed<PUBLISHER_IO_RETRY_SECONDS:
            raise leases.LeaseError('publisher_atomic_retry_budget_expired')
        try:
            leases.atomic_json(destination,value)
        except leases.LeaseError as error:
            if str(error) not in RETRYABLE_ATOMIC_CODES:raise
            elapsed=time.monotonic()-began
            if elapsed<0:raise leases.LeaseError('publisher_monotonic_invalid')
            if not elapsed<PUBLISHER_IO_RETRY_SECONDS:
                raise leases.LeaseError('publisher_atomic_retry_budget_expired') from None
            _last_retry_count+=1
            time.sleep(min(PUBLISHER_IO_RETRY_GAP_SECONDS,PUBLISHER_IO_RETRY_SECONDS-elapsed))
            continue
        elapsed=time.monotonic()-began
        if elapsed<0:raise leases.LeaseError('publisher_monotonic_invalid')
        if not elapsed<=PUBLISHER_IO_RETRY_SECONDS:
            raise leases.LeaseError('publisher_atomic_retry_budget_expired')
        if not leases.alive(owner):raise leases.LeaseError('publisher_parent_exited')
        return


def failure_diagnostic(error):
    """Best-effort fixed-enum side record, never a liveness or permission file."""
    try:
        binding=_failure_binding
        if (type(binding) is not dict or set(binding)!= {'controller_pid','controller_creation'}
                or type(binding['controller_pid']) is not int or not 0<binding['controller_pid']<=0xffffffff
                or type(binding['controller_creation']) is not str
                or re.fullmatch('[a-f0-9]{16}',binding['controller_creation']) is None):return
        directory=leases.physical(ROOT/'privacy-qa'/'runs',ROOT)
        destination=directory/f"publisher-failure-{binding['controller_pid']}-{binding['controller_creation']}-{os.getpid()}.json"
        leases.physical(destination,ROOT,missing=True)
        if destination.exists():return
        leases.atomic_json(destination,{'schema':1,'kind':'publisher_failure_diagnostic',
            **binding,'publisher_pid':os.getpid(),'at_unix':time.time(),
            'code':safe_failure_code(error),'retry_count':_last_retry_count,
            'diagnostic_only':True,'does_not_renew_source_or_lease':True})
    except Exception:
        # This record cannot make a failed write succeed or change exit policy.
        pass


def main():
    global _failure_binding
    _failure_binding=None
    parser=argparse.ArgumentParser()
    parser.add_argument('--controller-pid',type=int,required=True)
    args=parser.parse_args()
    owner=leases.identity(args.controller_pid)
    runtime=leases.read_json(ROOT/'environment-runtime.json',ROOT)
    if (owner is None or leases.parents().get(os.getpid())!=owner['pid']
            or os.path.normcase(owner['image'])!=os.path.normcase(runtime['node_executable'])):
        raise leases.LeaseError('publisher_parent_invalid')
    _failure_binding={'controller_pid':owner['pid'],'controller_creation':owner['creation']}
    destination=ROOT/'privacy-qa'/'runs'/f"environment-browser-{owner['pid']}.json"
    emit({'ready':True,'pid':os.getpid(),'controller_creation':owner['creation']})
    sequence=1
    while True:
        raw=sys.stdin.buffer.readline(MAX_FRAME+1)
        if not raw:return
        if not leases.alive(owner):
            raise leases.LeaseError('publisher_parent_exited')
        number,value=frame(raw,sequence)
        try:
            write_validated_status(owner,destination,value)
        except leases.LeaseError as error:
            # Only this local scheduling/I/O budget may be nonterminal. The
            # immutable frame is consumed, never re-timestamped or resubmitted.
            # A late atomic write may already exist, but keeps its original at;
            # admission freshness remains independently enforced by the guard.
            if str(error)!='publisher_atomic_retry_budget_expired':raise
            if not leases.alive(owner):raise leases.LeaseError('publisher_parent_exited')
            emit({'id':number,'ok':False,'retryable':True,
                  'code':'publisher_atomic_retry_budget_expired'})
        else:
            emit({'id':number,'ok':True})
        sequence+=1


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        failure_diagnostic(error)
        try:emit({'ok':False,'code':safe_failure_code(error)})
        except Exception:pass
        raise SystemExit(1)
