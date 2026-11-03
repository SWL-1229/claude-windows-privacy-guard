"""Compile only a fixture reader; --self-test never opens the WFP engine."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

DETECTOR=Path(__file__).resolve().parents[2]/'detector'
sys.path.insert(0,str(DETECTOR))
import prepare_wfp_audit as builder
import wfp_audit as audit


@unittest.skipUnless(os.name=='nt','Windows C# source-build fixture')
class ReadOnlyReaderBuildTests(unittest.TestCase):
    def test_builds_for_own_inventory_with_dynamic_scope_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            (root/'installed.json').write_text('{}')
            package='Claude_1.2.3.4_x64__pzs8sxrjxfjjc'
            app=root/package/'app';app.mkdir(parents=True)
            rows=[]
            for name in ('claude.exe','helper.exe'):
                path=app/name;path.write_bytes(b'fixture identity, not an executable')
                rows.append(dict(path=str(path),sha256=audit.sha(path)))
            inventory=root/'source-inventory.json'
            inventory.write_text(json.dumps(dict(schema=1,package=package,family='Claude_pzs8sxrjxfjjc',executable_count=2,executables=rows)))
            result=builder.prepare(root,inventory)
            self.assertTrue(result['read_only']);self.assertFalse(result['rules_modified'])
            manifest,image=audit.load_manifest(root)
            self.assertEqual(manifest['filter_count'],12)
            self.assertEqual(Path(image),app/'claude.exe')
            reader=root/manifest['reader'];self.assertTrue(reader.is_file())
            reader.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError,'audit_asset_changed'):audit.load_manifest(root)


if __name__=='__main__':unittest.main()
