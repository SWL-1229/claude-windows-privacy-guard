import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
import configure_brave as binding


class BraveBindingTests(unittest.TestCase):
    def test_signer_must_be_valid_and_exact_official_publisher(self):
        for valid, publisher, accepted in [(True,'Brave Software, Inc.',True),
                                            (False,'Brave Software, Inc.',False),
                                            (True,'Other Publisher',False)]:
            result=SimpleNamespace(returncode=0,stdout=json.dumps(dict(valid=valid,publisher=publisher,version='1.2.3.4')))
            with patch.object(binding.subprocess,'run',return_value=result):
                if accepted:self.assertEqual(binding.signed_version(Path('fixture.exe')),'1.2.3.4')
                else:
                    with self.assertRaises(ValueError):binding.signed_version(Path('fixture.exe'))

    def test_preparation_requires_signature_and_retains_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root/'build'; output.mkdir()
            (output/'hold.block').write_text(binding.HOLD, 'ascii')
            (output/'configured.json').write_text(json.dumps(dict(installed=False)))
            local = root/'local'
            exe = local/'BraveSoftware/Brave-Browser/Application/brave.exe'
            exe.parent.mkdir(parents=True); exe.write_bytes(b'offline fake binary, never launched')
            with patch.dict(os.environ, LOCALAPPDATA=str(local)), patch.object(binding, 'signed_version', return_value='1.2.3.4') as signed:
                self.assertFalse(binding.prepare(output)['installed'])
                signed.assert_called_once_with(exe)
                self.assertEqual((output/'hold.block').read_text('ascii'), binding.HOLD)
                with self.assertRaises(FileExistsError): binding.prepare(output)

    def test_signature_failure_writes_no_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root/'hold.block').write_text(binding.HOLD, 'ascii')
            (root/'configured.json').write_text('{"installed":false}')
            local=root/'local'; exe=local/'BraveSoftware/Brave-Browser/Application/brave.exe'
            exe.parent.mkdir(parents=True); exe.write_bytes(b'fixture; never launched')
            with patch.dict(os.environ, LOCALAPPDATA=str(local)), \
                 patch.object(binding, 'signed_version', side_effect=ValueError('invalid')) as signed:
                with self.assertRaises(ValueError): binding.prepare(root)
                signed.assert_called_once_with(exe)
            self.assertFalse((root/'brave-runtime.json').exists())


if __name__ == '__main__': unittest.main()
