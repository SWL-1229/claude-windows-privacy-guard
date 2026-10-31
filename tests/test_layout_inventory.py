"""Offline discovery tests; no real applications or user profiles are queried."""
import contextlib,importlib.util,io,json,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
try:
    spec=importlib.util.spec_from_file_location('layout_inventory_under_test',SCRIPTS/'layout_inventory.py')
    inventory=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventory)
finally:sys.path.pop(0)

class LayoutInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.local=self.base/'Local';self.roaming=self.base/'Roaming'
        self.root=self.local/'Claude-Data/claude_pzs8sxrjxfjjc';self.root.mkdir(parents=True)
        self.pkg={'PackageFamilyName':'Claude_pzs8sxrjxfjjc','PackageFullName':'Claude_fixture',
            'Version':'4.4212.0.0','InstallLocation':r'C:\Program Files\WindowsApps\Claude_fixture'}
        self.exe=self.pkg['InstallLocation']+r'\app\Claude.exe'

    def describe(self,args,exe=None):
        row={'ProcessId':123,'ExecutablePath':exe or self.exe,'CommandLine':'private raw command'}
        return inventory.describe_runtime([row],[self.exe],[self.root],lambda _:args)

    def test_runtime_known_modern_directory_and_no_secret_arguments_exposed(self):
        rows=self.describe([self.exe,'--type=renderer','--user-data-dir='+str(self.root),'--private=DO-NOT-REPORT'])
        self.assertEqual(rows[0]['layout'],'known');self.assertEqual(rows[0]['user_data_dir'],str(self.root))
        self.assertNotIn('DO-NOT-REPORT',json.dumps(rows));self.assertNotIn('private raw command',json.dumps(rows))

    def test_unknown_user_data_dir_is_review_needed_not_auto_approved(self):
        rows=self.describe([self.exe,'--user-data-dir='+str(self.base/'Custom')])
        self.assertEqual(rows[0]['layout'],'needs_review')

    def test_switch_after_separator_is_not_active(self):
        rows=self.describe([self.exe,'--','--user-data-dir='+str(self.root)])
        self.assertEqual(rows[0]['layout'],'not_exposed')

    def test_duplicates_and_relative_directories_refused(self):
        for flags in (['--user-data-dir=relative'],['--user-data-dir='+str(self.root)]*2):
            with self.subTest(flags=flags),self.assertRaisesRegex(RuntimeError,'ambiguous'):
                self.describe([self.exe,*flags])

    def test_foreign_process_not_treated_as_current_package(self):
        rows=self.describe(['not-read'],r'C:\Unrelated\Claude.exe')
        self.assertFalse(rows[0]['current_package_image']);self.assertEqual(rows[0]['layout'],'needs_review')

    def test_current_image_must_match_parsed_executable(self):
        with self.assertRaisesRegex(RuntimeError,'arguments_invalid'):self.describe([r'C:\Other\Claude.exe'])

    def test_closed_layout_does_not_claim_network_protection(self):
        r=inventory.build_report({'packages':[self.pkg],'processes':[]},self.local,self.roaming)
        self.assertTrue(r['cleanup_ready']);self.assertFalse(r['review_needed']);self.assertFalse(r['protection_verified'])

    def test_running_known_root_requires_exit_before_cleanup(self):
        row={'ProcessId':123,'ExecutablePath':self.exe,'CommandLine':'not-output'}
        r=inventory.build_report({'packages':[self.pkg],'processes':[row]},self.local,self.roaming,
            lambda _:[self.exe,'--user-data-dir='+str(self.root)])
        self.assertFalse(r['cleanup_ready']);self.assertFalse(r['review_needed'])

    def test_no_known_layout_or_package_requires_review(self):
        r=inventory.build_report({'packages':[],'processes':[]},self.local,self.roaming)
        self.assertTrue(r['review_needed']);self.assertFalse(r['cleanup_ready'])

    def test_failed_query_is_sanitized(self):
        with mock.patch.object(sys,'argv',['layout_inventory.py']),mock.patch.object(inventory,'query_windows',side_effect=RuntimeError('PRIVATE')):
            with contextlib.redirect_stdout(io.StringIO()) as out:code=inventory.main()
        self.assertEqual(code,2);self.assertNotIn('PRIVATE',out.getvalue());self.assertTrue(json.loads(out.getvalue())['review_needed'])

    def test_help_does_not_query_windows(self):
        with mock.patch.object(sys,'argv',['layout_inventory.py','--help']),mock.patch.object(inventory,'query_windows',side_effect=AssertionError('must not query')):
            with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(SystemExit) as e:inventory.main()
        self.assertEqual(e.exception.code,0)

if __name__=='__main__':unittest.main()
