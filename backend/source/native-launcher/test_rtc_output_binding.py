from pathlib import Path
import json
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import environment_lease as leases
import native_rtc_policy as rtc


class RtcOutputBindingTests(unittest.TestCase):
    def test_output_literal_uses_own_physical_root_and_safe_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();(root/'native-launcher').mkdir()
            raw=(Path(__file__).parent/'native_rtc_runtime.js').read_bytes()
            script,output=rtc.bound_runtime_script(raw,root,leases)
            self.assertEqual(output,str(root/'native-launcher/native-rtc-runtime.json'))
            self.assertIn('config.output!=='+json.dumps(output),script)
            self.assertNotIn('__CLAUDE_GUARD_RTC_OUTPUT__',script)

    def test_missing_or_duplicate_template_cannot_select_arbitrary_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();(root/'native-launcher').mkdir()
            for text in ('no token','__CLAUDE_GUARD_RTC_OUTPUT__ __CLAUDE_GUARD_RTC_OUTPUT__'):
                with self.assertRaises(ValueError):rtc.bound_runtime_script(text.encode(),root,leases)


if __name__=='__main__':unittest.main()
