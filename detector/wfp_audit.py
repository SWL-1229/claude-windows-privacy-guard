"""Read-only, version-bound WFP evidence for the observer panel.

This module cannot install/remove policy or grant network access. The pinned
reader compares native filter conditions with Windows-derived AppID/SID values.
"""
from pathlib import Path
import ctypes
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import time

TTL = 35.0
RULES = ('v4-address-not-gateway', 'v4-port-not-gateway',
         'v4-protocol-not-tcp', 'v6-block-all')
FLAGS = ('header_matches', 'condition_count_matches',
         'actual_identity_matches_windows_derived',
         'actual_forbidden_property_matches', 'exact_conditions_match', 'verified')


def elevated():
    try:
        return os.name == 'nt' and bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def physical(path, root):
    path, root = Path(path), Path(root)
    if not path.is_absolute() or path.resolve() != path or not path.is_relative_to(root):
        raise ValueError('audit_path_invalid')
    for part in (path, *path.parents):
        if part.exists() and (part.is_symlink() or getattr(part.stat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('audit_reparse_denied')
    return path


def read_json(path, root, limit=65536):
    path = physical(path, root)
    if not 0 < path.stat().st_size <= limit:
        raise ValueError('audit_file_size_invalid')
    value = json.loads(path.read_text('utf-8-sig'))
    if type(value) is not dict:
        raise ValueError('audit_object_invalid')
    return value


def sha(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(root):
    root = Path(root)
    value = read_json(root / 'detector/wfp-audit.json', root)
    required = {'schema', 'reader', 'reader_sha256', 'inventory', 'inventory_sha256',
                'package', 'family', 'executable_count', 'scope_count', 'filter_count'}
    if (set(value) != required or type(value['schema']) is not int or value['schema'] != 1
            or any(type(value[k]) is not int for k in ('executable_count', 'scope_count', 'filter_count'))
            or not 1 <= value['executable_count'] <= 128
            or value['scope_count'] != value['executable_count'] + 1
            or value['filter_count'] != value['scope_count'] * 4
            or value['family'] != 'Claude_pzs8sxrjxfjjc'
            or not re.fullmatch(r'Claude_[0-9.]+_x64__pzs8sxrjxfjjc', value['package'])):
        raise ValueError('audit_manifest_invalid')
    for key in ('reader', 'inventory'):
        relative = Path(value[key])
        if relative.is_absolute() or '..' in relative.parts or relative.parts[0] != 'maintenance':
            raise ValueError('audit_asset_invalid')
        asset = physical(root / relative, root)
        expected = value[key + '_sha256']
        if not re.fullmatch('[0-9a-f]{64}', expected) or sha(asset) != expected:
            raise ValueError('audit_asset_changed')
    if Path(value['reader']).name != 'DetailedWfpReadOnly.exe':
        raise ValueError('audit_reader_invalid')
    inventory = read_json(root / value['inventory'], root)
    if (inventory.get('schema') != 1 or inventory.get('package') != value['package']
            or inventory.get('family') != value['family']
            or inventory.get('executable_count') != value['executable_count']
            or not isinstance(inventory.get('executables'), list)
            or len(inventory['executables']) != value['executable_count']):
        raise ValueError('audit_inventory_invalid')
    main = [row.get('path') for row in inventory['executables']
            if type(row) is dict and Path(row.get('path', '')).name.lower() == 'claude.exe']
    if len(main) != 1:
        raise ValueError('audit_main_identity_invalid')
    return value, main[0]


def verdict(value, manifest):
    """No count-only, old installation-marker, or self-declared green results."""
    if type(value) is not dict:
        return 'unknown', 'audit_result_unavailable'
    code = value.get('error_code', '')
    if code:
        if not isinstance(code, str):
            return 'unknown', 'audit_result_invalid'
        if code.endswith('_0x00000005'):
            return 'unknown', 'administrator_required'
        if code in ('filter_get_0x80320003', 'provider_get_0x80320005', 'sublayer_get_0x80320007'):
            return 'fail', 'required_kernel_rule_missing'
        return 'unknown', 'audit_reader_unavailable'
    required = {'schema': 1, 'read_only': True, 'settings_mutated': False,
                'inventory_pin_verified': True, 'only_expected_provider_queried': True,
                'provider_sublayer_verified': True, 'raw_identity_blobs_exported': False,
                'packet_enforcement_tested': False}
    if any(type(value.get(k)) is not type(expected) or value[k] != expected
           for k, expected in required.items()):
        return ('fail', 'kernel_provider_or_conditions_invalid') if value.get('provider_sublayer_verified') is False else ('unknown', 'audit_result_invalid')
    rows = value.get('conditions')
    if (type(value.get('expected_filters')) is not int
            or value['expected_filters'] != manifest['filter_count']
            or not isinstance(rows, list) or len(rows) != manifest['filter_count']):
        return 'fail', 'kernel_rule_set_incomplete'
    seen, keys, ids = set(), set(), set()
    for row in rows:
        if type(row) is not dict:
            return 'unknown', 'audit_result_invalid'
        index, rule = row.get('scope_index'), row.get('rule')
        if (type(index) is not int or not 0 <= index < manifest['scope_count'] or rule not in RULES
                or (index, rule) in seen
                or row.get('scope_kind') != ('package_sid' if index == manifest['executable_count'] else 'executable_app_id')
                or any(row.get(k) is not True for k in FLAGS)
                or not isinstance(row.get('key'), str)
                or not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', row['key'])
                or type(row.get('id')) is not int or row['id'] <= 0
                or row['key'] in keys or row['id'] in ids):
            return 'fail', 'kernel_rule_identity_or_condition_mismatch'
        seen.add((index, rule)); keys.add(row['key']); ids.add(row['id'])
    if value.get('verified') is not True:
        return 'fail', 'kernel_conditions_not_verified'
    return 'pass', 'exact_live_kernel_conditions_verified'


def collect(root, package_getter, *, run=subprocess.run, clock=time.time):
    began = clock()
    output = {'state': 'unknown', 'reason': 'audit_pending', 'checked_at': began,
              'read_only': True, 'packet_enforcement_tested': False}
    try:
        manifest, image = load_manifest(root)
        before = package_getter()
        if before != manifest['package']:
            raise ValueError('current_package_requires_new_audit')
        result = run([str(Path(root) / manifest['reader'])], capture_output=True, text=True,
                     encoding='utf-8-sig', errors='strict', timeout=12, creationflags=0x08000000)
        if len(result.stdout) > 65536:
            raise ValueError('audit_result_invalid')
        value = json.loads(result.stdout)
        state, reason = verdict(value, manifest)
        ended = clock()
        # Recheck the running installation and pinned executable after the query.
        if package_getter() != before or sha(Path(root) / manifest['reader']) != manifest['reader_sha256']:
            raise ValueError('current_package_or_reader_changed')
        if not 0 <= ended - began <= 15:
            raise ValueError('audit_query_timing_invalid')
        if state == 'pass':
            try:
                stamp = dt.datetime.fromisoformat(value['at_utc'].replace('Z', '+00:00'))
                if stamp.utcoffset() != dt.timedelta(0) or not began - .01 <= stamp.timestamp() <= ended + .01:
                    raise ValueError()
            except Exception:
                raise ValueError('audit_measurement_time_invalid') from None
            if result.returncode != 0:
                raise ValueError('audit_reader_return_code_invalid')
            output.update(filter_count=manifest['filter_count'], scope_count=manifest['scope_count'],
                          main_image=image, package=manifest['package'])
        output.update(state=state, reason=reason)
    except Exception as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch('[a-z_]{3,80}', str(error)) else 'audit_read_unavailable'
        output.update(state='unknown', reason=reason)
    return output


def native_row(evidence, target, now):
    """Bind displayed kernel evidence to the current native target and time."""
    if not isinstance(evidence, dict):
        return 'unknown', '点击【管理员核验】读取当前内核规则', None
    when = evidence.get('checked_at')
    if type(when) not in (int, float) or not 0 <= now - when <= TTL:
        return 'unknown', '内核证据已过期，等待重新核验', when if type(when) in (int, float) else None
    state = evidence.get('state')
    if state == 'pass':
        if os.path.normcase(target.get('image', '')) != os.path.normcase(evidence.get('main_image', '')):
            return 'unknown', '当前 Claude 进程不在已核验程序范围', when
        return 'pass', f"IPv6／非 TCP 阻断有效 · {evidence['filter_count']} 条规则", when
    if state == 'fail':
        return 'fail', '当前内核规则缺失、禁用或条件不匹配', when
    if evidence.get('reason') == 'administrator_required':
        return 'unknown', '需要管理员只读权限，点击【管理员核验】', when
    return 'unknown', '当前内核规则尚未核实 · ' + str(evidence.get('reason', 'audit_pending')), when
