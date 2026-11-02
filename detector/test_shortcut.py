from pathlib import Path
import tempfile
import unittest
import install_shortcut as shortcut


class ShortcutTests(unittest.TestCase):
    def fixture(self,path):
        root=path/'guard';desktop=path/'desktop';root.mkdir();desktop.mkdir()
        for item in shortcut.REQUIRED:
            target=root/item;target.parent.mkdir(parents=True,exist_ok=True);target.write_text('fixture')
        python=path/'pythonw.exe';python.write_text('fixture')
        app=path/'app.py';app.write_text('# fixture')
        return root,desktop,python,app

    def test_prepare_does_not_write_or_mutate_guard(self):
        with tempfile.TemporaryDirectory() as folder:
            root,desktop,python,app=self.fixture(Path(folder).resolve())
            before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            plan=shortcut.prepare(root,desktop,python=python,app=app)
            self.assertEqual(plan['root'],root)
            self.assertEqual(list(desktop.iterdir()),[])
            self.assertEqual(before,{p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_missing_guard_is_not_an_install_request(self):
        with tempfile.TemporaryDirectory() as folder:
            root,desktop,python,app=self.fixture(Path(folder).resolve())
            (root/'installed.json').unlink()
            with self.assertRaisesRegex(ValueError,'existing_guard_installation_required'):
                shortcut.prepare(root,desktop,python=python,app=app)
            self.assertEqual(list(desktop.iterdir()),[])

    def test_existing_shortcut_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            root,desktop,python,app=self.fixture(Path(folder).resolve())
            link=desktop/'Claude 运行环境面板.lnk';link.write_bytes(b'user link')
            with self.assertRaisesRegex(ValueError,'shortcut_already_exists'):
                shortcut.prepare(root,desktop,python=python,app=app)
            self.assertEqual(link.read_bytes(),b'user link')


if __name__=='__main__':unittest.main()
