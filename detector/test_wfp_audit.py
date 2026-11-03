import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import uuid

import checks
import monitor
import wfp_audit as w
import test_monitor as base_tests

PACKAGE = 'Claude_4.4212.0.0_x64__pzs8sxrjxfjjc'
IMAGE = r'C:\Program Files\WindowsApps\Claude_4.4212.0.0_x64__pzs8sxrjxfjjc\app\claude.exe'


def metadata():
    return {'filter_count': 36, 'scope_count': 9, 'executable_count': 8}


def proof(now=None):
    rows = []
    for index in range(9):
        for rule in w.RULES:
            rows.append(dict(scope_index=index, rule=rule,
                             scope_kind='package_sid' if index == 8 else 'executable_app_id',
                             key=str(uuid.uuid4()), id=len(rows) + 1,
                             **{key: True for key in w.FLAGS}))
    return dict(schema=1, read_only=True, settings_mutated=False,
                at_utc=checks.stamp(time.time() if now is None else now),
                inventory_pin_verified=True, only_expected_provider_queried=True,
                provider_sublayer_verified=True, raw_identity_blobs_exported=False,
                packet_enforcement_tested=False, expected_filters=36,
                verified=True, conditions=rows)


class VerdictTests(unittest.TestCase):
    def test_exact_current_conditions_pass(self):
        self.assertEqual(w.verdict(proof(), metadata())[0], 'pass')

    def test_permission_is_unknown_not_a_leak_or_pass(self):
        self.assertEqual(w.verdict({'error_code': 'provider_get_0x00000005'}, metadata()),
                         ('unknown', 'administrator_required'))

    def test_missing_kernel_rule_is_failure(self):
        for code in ('filter_get_0x80320003', 'provider_get_0x80320005', 'sublayer_get_0x80320007'):
            self.assertEqual(w.verdict({'error_code': code}, metadata())[0], 'fail')

    def test_count_only_and_historical_installation_marker_never_pass(self):
        self.assertNotEqual(w.verdict({'filterCount': 36, 'verified': True}, metadata())[0], 'pass')

    def test_each_header_identity_and_condition_flag_is_required(self):
        for flag in w.FLAGS:
            value = proof(); value['conditions'][0][flag] = False
            self.assertEqual(w.verdict(value, metadata())[0], 'fail', flag)

    def test_disabled_provider_rejected(self):
        value = proof(); value['provider_sublayer_verified'] = False
        self.assertEqual(w.verdict(value, metadata())[0], 'fail')

    def test_missing_or_duplicate_scope_rule_rejected(self):
        for alter in (lambda r: r.pop(), lambda r: r.__setitem__(1, copy.deepcopy(r[0]))):
            value = proof(); alter(value['conditions'])
            self.assertEqual(w.verdict(value, metadata())[0], 'fail')

    def test_wrong_scope_kind_and_boolean_index_rejected(self):
        for key, change in [('scope_kind', 'wrong'), ('scope_index', True), ('id', True), ('id', 0)]:
            value = proof(); value['conditions'][0][key] = change
            self.assertEqual(w.verdict(value, metadata())[0], 'fail')

    def test_duplicate_runtime_id_and_key_rejected(self):
        for key in ('id', 'key'):
            value = proof(); value['conditions'][1][key] = value['conditions'][0][key]
            self.assertEqual(w.verdict(value, metadata())[0], 'fail')

    def test_mutating_or_packet_test_claim_not_accepted_as_readonly_evidence(self):
        for key, change in [('settings_mutated', True), ('read_only', False), ('packet_enforcement_tested', True)]:
            value = proof(); value[key] = change
            self.assertNotEqual(w.verdict(value, metadata())[0], 'pass')


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / 'detector').mkdir(); (self.root / 'maintenance').mkdir()
        self.reader = self.root / 'maintenance/DetailedWfpReadOnly.exe'
        self.reader.write_bytes(b'fixture; never executable')
        inventory = self.root / 'maintenance/inventory.json'
        inventory.write_text(json.dumps({'schema': 1, 'package': PACKAGE, 'family': 'Claude_pzs8sxrjxfjjc',
                                        'executable_count': 8, 'executables': [{'path': IMAGE}] +
                                        [{'path': rf'C:\fixture\helper{i}.exe'} for i in range(7)]}))
        self.manifest = dict(schema=1, reader='maintenance/DetailedWfpReadOnly.exe',
                             reader_sha256=w.sha(self.reader), inventory='maintenance/inventory.json',
                             inventory_sha256=w.sha(inventory), package=PACKAGE, family='Claude_pzs8sxrjxfjjc',
                             **metadata())
        self.manifest_path = self.root / 'detector/wfp-audit.json'
        self.write_manifest()
        self.now = time.time()
        self.runner = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(proof(self.now)), ''))

    def write_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest))

    def collect(self, getter=None):
        return w.collect(self.root, getter or Mock(return_value=PACKAGE), run=self.runner,
                         clock=Mock(side_effect=[self.now, self.now + .5]))

    def test_pinned_readonly_command_and_fresh_measurement_pass(self):
        value = self.collect()
        self.assertEqual(value['state'], 'pass')
        self.assertEqual(value['main_image'], IMAGE)
        self.assertEqual(self.runner.call_args.args[0], [str(self.reader)])
        self.assertFalse(value['packet_enforcement_tested'])

    def test_reader_tampering_does_not_execute(self):
        self.reader.write_bytes(b'changed')
        self.assertEqual(self.collect()['state'], 'unknown'); self.runner.assert_not_called()

    def test_unrelated_executable_or_path_escape_never_executes(self):
        for path in ('../other.exe', 'maintenance/not-the-reader.exe'):
            self.manifest['reader'] = path; self.write_manifest()
            self.assertEqual(self.collect()['state'], 'unknown')
        self.runner.assert_not_called()

    def test_current_package_change_requires_new_audit(self):
        self.assertEqual(self.collect(Mock(return_value='Claude_new_package'))['state'], 'unknown')
        self.runner.assert_not_called()

    def test_package_change_during_query_cannot_pass(self):
        self.assertEqual(self.collect(Mock(side_effect=[PACKAGE, 'changed']))['state'], 'unknown')

    def test_stale_or_future_measurement_cannot_pass(self):
        for change in (-60, 60):
            self.runner.return_value.stdout = json.dumps(proof(self.now + change))
            self.assertEqual(self.collect()['state'], 'unknown')

    def test_failure_return_code_cannot_fake_pass(self):
        self.runner.return_value.returncode = 2
        self.assertEqual(self.collect()['state'], 'unknown')

    def test_access_denial_and_timeout_never_pass(self):
        self.runner.return_value = subprocess.CompletedProcess([], 2, '{"error_code":"provider_get_0x00000005"}', '')
        self.assertEqual(self.collect()['reason'], 'administrator_required')
        self.runner.side_effect = subprocess.TimeoutExpired('fixed-reader', 12)
        self.assertEqual(self.collect()['state'], 'unknown')

    def test_raw_private_errors_never_reach_panel(self):
        self.runner.side_effect = OSError('PRIVATE-SECRET-CONTENT')
        self.assertNotIn('PRIVATE', json.dumps(self.collect()))


class EvidenceRowTests(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        self.evidence = dict(state='pass', checked_at=self.now - 1, main_image=IMAGE, filter_count=36)

    def test_current_identity_passes_with_rule_scope_label(self):
        state, value, stamp = w.native_row(self.evidence, {'image': IMAGE}, self.now)
        self.assertEqual(state, 'pass'); self.assertIn('规则', value)
        self.assertEqual(stamp, self.evidence['checked_at'])

    def test_stale_and_future_evidence_remove_green(self):
        for value in (self.now - 40, self.now + 1):
            self.evidence['checked_at'] = value
            self.assertEqual(w.native_row(self.evidence, {'image': IMAGE}, self.now)[0], 'unknown')

    def test_other_version_or_executable_cannot_inherit_green(self):
        self.assertEqual(w.native_row(self.evidence, {'image': r'C:\other\claude.exe'}, self.now)[0], 'unknown')

    def test_missing_proof_and_access_denial_stay_unknown(self):
        self.assertEqual(w.native_row(None, {}, self.now)[0], 'unknown')
        value = dict(state='unknown', checked_at=self.now, reason='administrator_required')
        self.assertIn('管理员', w.native_row(value, {}, self.now)[1])

    def test_kernel_mismatch_is_visible_failure(self):
        self.evidence['state'] = 'fail'
        self.assertEqual(w.native_row(self.evidence, {'image': IMAGE}, self.now)[0], 'fail')


class PanelIntegrationTests(unittest.TestCase):
    def test_verified_native_rule_has_own_timestamp_and_ttl(self):
        fixture = base_tests.LiveEvidenceTests(); fixture.setUp()
        with tempfile.TemporaryDirectory() as temp:
            live = fixture.fixture(temp)
            live.wfp = dict(state='pass', checked_at=fixture.now - 2,
                            main_image=fixture.target['image'], filter_count=36)
            rows = {row['key']: row for row in live.snapshot()['rows']}
            row = rows['desktop0_ipv6']
            self.assertEqual(row['state'], 'pass')
            self.assertEqual(row['ttl_seconds'], w.TTL)
            self.assertAlmostEqual(checks.epoch(row['measured_at']), fixture.now - 2, places=5)
            self.assertEqual(checks.effective_state(row, fixture.now + 40), 'unknown')

    def test_permission_missing_not_hidden_by_green_runtime(self):
        fixture = base_tests.LiveEvidenceTests(); fixture.setUp()
        with tempfile.TemporaryDirectory() as temp:
            live = fixture.fixture(temp)
            self.assertEqual({row['key']: row for row in live.snapshot()['rows']}['desktop0_ipv6']['state'], 'unknown')

    def test_browser_green_is_explicitly_policy_scope_not_kernel_test(self):
        fixture = base_tests.LiveEvidenceTests(); fixture.setUp()
        with tempfile.TemporaryDirectory() as temp:
            live = fixture.fixture(temp)
            live.leases.NATIVE_BROWSER_MODE = 'native_process_policy_v1'
            record = dict(fixture.record, kind='browser', verification_mode=live.leases.NATIVE_BROWSER_MODE,
                          source=str(Path(temp) / 'browser-source.json'))
            live.registrations = lambda: [record]
            rows = {row['key']: row for row in live.snapshot()['rows']}
            row = rows['browser0_ipv6']
            self.assertEqual(row['state'], 'pass')
            self.assertIn('路由策略', row['name'])
            self.assertIn('不声称', row['detail'])
            self.assertNotIn('WFP', row['source'])
            self.assertEqual(row['ttl_seconds'], 4)

    def test_unknown_browser_mode_cannot_inherit_native_policy_pass(self):
        fixture = base_tests.LiveEvidenceTests(); fixture.setUp()
        with tempfile.TemporaryDirectory() as temp:
            live = fixture.fixture(temp)
            live.leases.NATIVE_BROWSER_MODE = 'native_process_policy_v1'
            record = dict(fixture.record, kind='browser', verification_mode='unrecognized',
                          source=str(Path(temp) / 'browser-source.json'))
            live.registrations = lambda: [record]
            rows = {row['key']: row for row in live.snapshot()['rows']}
            self.assertEqual(rows['browser0_ipv6']['state'], 'unknown')


if __name__ == '__main__':
    unittest.main()
