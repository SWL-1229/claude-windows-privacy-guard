from pathlib import Path
import json,tempfile,unittest
import manual_browser_policy as policy

class ProfilePreferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root=Path(self.temp.name)
        self.file=self.root/'browser-profiles/edge-claude/Default/Preferences'
        self.file.parent.mkdir(parents=True)
    def tearDown(self):self.temp.cleanup()
    def write(self,value):self.file.write_text(json.dumps(value),'utf-8')
    def test_creates_actual_pref(self):
        policy.prepare_webrtc_preferences(self.root)
        policy.require_webrtc_preferences(self.root)
    def test_preserves_other_profile_settings(self):
        before={'session':{'restore_on_startup':4},'example_retained_setting':['a','b'],'webrtc':{'retained':True}}
        self.write(before);policy.prepare_webrtc_preferences(self.root)
        after=json.loads(self.file.read_text());after['webrtc'].pop('ip_handling_policy')
        self.assertEqual(after,before)
    def test_invalid_json_untouched(self):
        self.file.write_text('{broken','utf-8')
        with self.assertRaises(Exception):policy.prepare_webrtc_preferences(self.root)
        self.assertEqual(self.file.read_text(),'{broken')
    def test_wrong_root_type_untouched(self):
        self.write([]);before=self.file.read_bytes()
        with self.assertRaises(Exception):policy.prepare_webrtc_preferences(self.root)
        self.assertEqual(self.file.read_bytes(),before)
    def test_wrong_webrtc_type_untouched(self):
        self.write({'webrtc':False});before=self.file.read_bytes()
        with self.assertRaises(Exception):policy.prepare_webrtc_preferences(self.root)
        self.assertEqual(self.file.read_bytes(),before)
    def test_idempotent(self):
        policy.prepare_webrtc_preferences(self.root);before=self.file.stat().st_mtime_ns
        policy.prepare_webrtc_preferences(self.root);self.assertEqual(self.file.stat().st_mtime_ns,before)
    def test_removal_rejected(self):
        self.write({'webrtc':{'ip_handling_policy':'default'}})
        with self.assertRaises(Exception):policy.require_webrtc_preferences(self.root)
    def test_realistic_large_preferences_preserved(self):
        value={'retained_data':'a'*150000}
        self.write(value);policy.prepare_webrtc_preferences(self.root)
        after=json.loads(self.file.read_text());self.assertEqual(after['retained_data'],value['retained_data'])
        policy.require_webrtc_preferences(self.root)

if __name__=='__main__':unittest.main()
