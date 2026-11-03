"""Offline browser contracts; never query or launch an installed browser."""
from pathlib import Path
import copy
import unittest
from unittest.mock import patch
import brave_browser_policy as policy
import environment_lease as leases
from test_manual_mode import ManualSourceTests, RegistryIntegrationTests
from test_profile_pref import ProfilePreferenceTests


class BraveProfileTests(ProfilePreferenceTests):
    def setUp(self):
        super().setUp()
        self.file=self.root/'browser-profiles/brave-claude/Default/Preferences'
        self.file.parent.mkdir(parents=True)

    def test_creates_actual_pref(self):
        with patch('test_profile_pref.policy', policy): super().test_creates_actual_pref()

    def run(self, result=None):
        # Run the same preservation/malformed-data cases against Brave's profile.
        with patch('test_profile_pref.policy', policy): return super().run(result)


class BraveRegistryTests(RegistryIntegrationTests):
    def setUp(self):
        super().setUp()
        self.record['verification_mode']=policy.MODE
        self.value['verification_mode']=policy.MODE
        self.value['environment_scope']=policy.SCOPE
        self.value['native_baseline']['scope']=policy.SCOPE
        self.value['native_baseline']['browser_binding_sha256']='e'*64
        self.record['startup_runtime_sha256']=leases.native_startup_fingerprint(self.value['native_baseline'])
        pin=patch.object(policy,'browser_executable',return_value=self.target['image'])
        pin.start();self.addCleanup(pin.stop)

    def test_wrong_browser_identity_denied(self):
        with patch.object(policy,'browser_executable',return_value=r'C:\OtherBrowser.exe'):
            self.assertEqual(self.registry.transmission_state()['state'],'denied')

    def test_binding_baseline_change_denied(self):
        self.value['native_baseline']['browser_binding_sha256']='f'*64
        self.assertEqual(self.registry.transmission_state()['state'],'denied')


class BraveArgumentsTests(unittest.TestCase):
    def test_separate_profile_without_automation_or_fingerprint_injection(self):
        args=policy.arguments(Path(r'C:\fixture\guard'))
        self.assertIn('brave-claude',args[0])
        for forbidden in ['remote-debugging','headless','enable-automation','automationcontrolled','host-resolver-rules','user-agent=']:
            self.assertNotIn(forbidden, ' '.join(args).lower())

    def test_rejects_other_contract_and_arbitrary_navigation(self):
        fixture=ManualSourceTests();fixture.setUp()
        with self.assertRaises(leases.LeaseError): policy.source(fixture.value,fixture.record,fixture.now,leases)
        with self.assertRaises(ValueError): policy.arguments(Path(r'C:\fixture\guard'),'https://other.example/')


if __name__=='__main__': unittest.main()
