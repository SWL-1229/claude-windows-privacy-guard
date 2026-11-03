import copy
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import time
import unittest
from unittest.mock import Mock, patch

import environment_lease as leases
import manual_browser_policy as policy


def stamp(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


class ManualSourceTests(unittest.TestCase):
    def setUp(self):
        self.now = round(time.time(), 3)
        born = self.now - 60
        self.target = {'pid': 10, 'creation': f'{int((born + 11644473600) * 10000000):016x}', 'image': r'C:\Edge.exe'}
        baseline = {'schema': 1, 'scope': policy.SCOPE, 'checked_at': stamp(self.now - 20),
                    'timezone': 'America/Denver', 'windows_timezone': 'Mountain Standard Time',
                    'language_preference': 'en-US,en', 'launcher_sha256': 'a' * 64}
        self.value = {'schema_version': 1, 'kind': 'browser', 'verification_mode': policy.MODE,
                      'environment_scope': policy.SCOPE, 'process_pid': 10, 'status': 'monitoring',
                      'native_baseline': baseline, 'controller_heartbeat_checked_at': stamp(self.now - .2),
                      'at': stamp(self.now - .1), 'error_codes': [],
                      'page_javascript_measured': False, 'ice_candidates_measured': False}
        self.record = {'kind': 'browser', 'verification_mode': policy.MODE, 'target': self.target,
                       'bootstrap_checked_at': self.now - 1,
                       'startup_runtime_sha256': leases.native_startup_fingerprint(baseline)}

    def check(self):
        return leases.native_browser_source(self.value, self.record, self.now)

    def test_native_policy_source_is_explicitly_distinct_from_js_or_ice_proof(self):
        value = self.check()
        self.assertEqual(value['bootstrap_checked_at'], self.now - 1)
        self.assertFalse(self.value['page_javascript_measured'])
        self.assertNotIn('startup_runtime', self.value)

    def test_no_page_or_ice_measurement_claim_can_be_forged(self):
        for field in ('page_javascript_measured', 'ice_candidates_measured'):
            self.value[field] = True
            with self.assertRaises(leases.LeaseError): self.check()
            self.value[field] = False

    def test_stale_and_future_heartbeat_never_grant(self):
        for value in (self.now - 5, self.now + 1):
            self.value['controller_heartbeat_checked_at'] = stamp(value)
            with self.assertRaises(leases.LeaseError): self.check()

    def test_baseline_change_cannot_inherit_old_registration(self):
        self.value['native_baseline']['launcher_sha256'] = 'b' * 64
        with self.assertRaises(leases.LeaseError): self.check()

    def test_new_york_or_tokyo_timezone_never_passes_denver_policy(self):
        for zone in ('America/New_York', 'Asia/Tokyo'):
            self.value['native_baseline']['timezone'] = zone
            with self.assertRaises(leases.LeaseError): self.check()

    def test_wrong_target_or_scope_rejected(self):
        for field, bad in [('process_pid', 11), ('environment_scope', leases.NATIVE_BROWSER_SCOPE),
                           ('status', 'stopped'), ('error_codes', ['failed'])]:
            before = copy.deepcopy(self.value); self.value[field] = bad
            with self.assertRaises(leases.LeaseError): self.check()
            self.value = before

    def test_unknown_mode_never_uses_manual_contract(self):
        self.record['verification_mode'] = 'unknown'
        with self.assertRaises(leases.LeaseError): self.check()


class ActualArgumentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(r'C:\fixture\guard')
        self.target = {'pid': 10, 'creation': '0000000000000010', 'image': r'C:\Edge.exe'}
        self.controller = {'pid': 9, 'creation': '0000000000000009', 'image': r'C:\pythonw.exe'}
        self.actual = {10: [self.target['image'], *policy.arguments(self.root)],
                       9: [self.controller['image'], '-E', '-s', '-B', str(self.root / 'claude_browser_launch.py')]}
        self.api = Mock(); self.api.read_arguments.side_effect = lambda pid: self.actual[pid]
        self.identities = {10: self.target, 9: self.controller}
        self.lease = Mock(); self.lease.LeaseError = leases.LeaseError
        self.lease.identity.side_effect = lambda pid: self.identities[pid]
        self.lease.same_identity.side_effect = lambda left, right: left == right

    def check(self):
        return policy.actual_arguments(self.root, self.target, self.controller, self.lease, self.api)

    def test_normal_browser_with_fixed_protection_arguments_passes(self):
        self.assertEqual(len(self.check()), 64)

    def test_no_remote_debugging_or_automation_hiding_switches(self):
        args = policy.arguments(self.root)
        for text in ('remote-debugging', 'headless', 'AutomationControlled', 'host-resolver-rules', 'user-agent='):
            self.assertFalse(any(text in arg for arg in args))
        self.assertIn('--proxy-server=http://127.0.0.1:17894', args)
        self.assertIn('--force-webrtc-ip-handling-policy=disable_non_proxied_udp', args)

    def test_wrong_proxy_cannot_bypass_native_policy(self):
        self.actual[10][self.actual[10].index('--proxy-server=http://127.0.0.1:17894')] = '--proxy-server=direct://'
        with self.assertRaises(leases.LeaseError): self.check()

    def test_actual_debugger_or_extra_script_flag_is_rejected(self):
        self.actual[10].append('--remote-debugging-pipe')
        with self.assertRaises(leases.LeaseError): self.check()

    def test_unrelated_python_controller_is_rejected(self):
        self.actual[9][-1] = str(self.root / 'unrelated.py')
        with self.assertRaises(leases.LeaseError): self.check()

    def test_reused_target_pid_cannot_pass(self):
        self.identities[10] = dict(self.target, creation='0000000000000020')
        with self.assertRaises(leases.LeaseError): self.check()

    def test_browser_url_handoff_does_not_accept_arbitrary_url(self):
        with self.assertRaises(ValueError): policy.arguments(self.root, 'https://unrelated.example/')


class NativeMetadataTests(unittest.TestCase):
    def setUp(self):
        p = Path(__file__).parent / 'native-launcher/native_desktop_launch.py'
        spec = importlib.util.spec_from_file_location('denver_native_test', p)
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.now = time.time()
        self.value = dict(origin='https://claude.ai', topFrame=True, timeZone='America/Denver',
                          language='en-US', januaryOffset=420, julyOffset=360,
                          nonce='fixture_nonce_value_123456', epoch=self.now * 1000)

    def test_denver_and_both_seasonal_offsets(self):
        self.assertEqual(self.m.metadata(self.value, real_origin=True, now=self.now)['timeZone'], 'America/Denver')

    def test_old_new_york_or_wrong_dst_offsets_rejected(self):
        for field, value in [('timeZone', 'America/New_York'), ('timeZone', 'Asia/Tokyo'),
                             ('januaryOffset', 300), ('julyOffset', 240), ('julyOffset', 420)]:
            data = dict(self.value, **{field: value})
            with self.assertRaises(self.m.LaunchError): self.m.metadata(data, real_origin=True, now=self.now)


class RegistryIntegrationTests(unittest.TestCase):
    def setUp(self):
        f = ManualSourceTests(); f.setUp()
        self.now, self.target, self.value = f.now, f.target, f.value
        self.root = Path(r'C:\fixture\guard')
        self.controller = {'pid': 9, 'creation': f'{int((self.now - 70 + 11644473600) * 10000000):016x}',
                           'image': str(self.root / 'pythonw.exe')}
        self.monitor = {'pid': 11, 'creation': f'{int((self.now - 50 + 11644473600) * 10000000):016x}',
                        'image': str(self.root / 'pythonw.exe')}
        self.source = self.root / 'privacy-qa/runs/environment-browser-9.json'
        self.record = dict(f.record, schema=1, monitor=self.monitor, controller=self.controller,
                           source=str(self.source), nonce='a' * 32, registered_at=self.now - .5,
                           native_arguments_sha256='d' * 64)
        self.payload = dict(schema=1, nonce='a' * 32, ok=True, checked_at=self.now - .2,
                            written_at=self.now - .1, reason=leases.NATIVE_BROWSER_REASON)
        ids = {10: self.target, 9: self.controller, 11: self.monitor}
        self.registry = leases.LeaseRegistry(self.root, get_identity=lambda pid: copy.deepcopy(ids.get(pid)),
            get_parents=lambda: {10: 9}, clock=lambda: self.now, get_creations=None)
        self.registry.scan = lambda **kw: None
        self.registry.active = lambda: [(copy.deepcopy(self.record), self.root / 'lease.json', True)]
        def read(path, root):
            if Path(path) == self.root / 'environment-runtime.json':
                return {'browser_executable': self.target['image'],
                        'python_executable': str(self.root / 'python.exe'), 'node_executable': str(self.root / 'node.exe')}
            return copy.deepcopy(self.value if Path(path) == self.source else self.payload)
        self.patcher = patch.object(leases, 'read_json', side_effect=read)
        self.patcher.start(); self.addCleanup(self.patcher.stop)

    def test_actual_registry_accepts_explicit_manual_native_contract(self):
        result = self.registry.transmission_state()
        self.assertEqual(result['state'], 'permitted', result)
        self.assertTrue(result['native_process_policy_only'])
        self.assertIsNone(result['browser_runtime_verified_at'])

    def test_stale_actual_observation_not_renewed_by_controller_heartbeat(self):
        self.payload['checked_at'] = self.now - 5
        self.assertEqual(self.registry.transmission_state()['state'], 'denied')

    def test_false_lease_never_suspends_into_manual_permission(self):
        self.payload.update(ok=False, reason='browser_scope_suspension_pending')
        self.assertEqual(self.registry.transmission_state()['state'], 'denied')

    def test_changed_baseline_or_unknown_mode_denies(self):
        self.value['native_baseline']['launcher_sha256'] = 'b' * 64
        self.assertEqual(self.registry.transmission_state()['state'], 'denied')
        self.record['verification_mode'] = 'unknown'
        self.assertEqual(self.registry.transmission_state()['state'], 'denied')


if __name__ == '__main__': unittest.main()
