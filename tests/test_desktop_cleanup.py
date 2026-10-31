"""Offline regression tests. All stores are disposable fixtures, never real profiles."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "desktop_cleanup.py"
SPEC = importlib.util.spec_from_file_location("desktop_cleanup_under_test", SCRIPT)
cleanup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cleanup)


class DesktopCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="claude-cleanup-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "Claude"
        self.root.mkdir()
        # A missed main() mock must fail before executing any process query.
        self.no_processes = mock.patch.object(
            cleanup, "powershell", side_effect=AssertionError("Real process discovery is forbidden in these tests")
        )
        self.no_processes.start()
        self.addCleanup(self.no_processes.stop)

    def write(self, relative, content=b"fixture"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return path

    def make_cookies(self, relative="Network/Cookies", count=3, recognized=True):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.closing(sqlite3.connect(path)) as connection:
            with connection:
                table = "cookies" if recognized else "unexpected_schema"
                connection.execute(f"CREATE TABLE {table} (host_key TEXT, encrypted_value BLOB)")
                connection.executemany(
                    f"INSERT INTO {table} VALUES (?, ?)",
                    [(".claude.ai", b"not-a-real-cookie") for _ in range(count)],
                )
        return path

    def snapshot(self, root=None):
        root = root or self.root
        return {
            str(path.relative_to(root)): path.read_bytes() if path.is_file() else None
            for path in sorted(root.rglob("*"))
        }

    def populate(self):
        self.make_cookies(count=3)
        self.make_cookies("Cookies", count=1)
        self.write("Cache/cache.data", "old cache")
        self.write("Local Storage/leveldb/log", "old authentication")
        self.write("Sessions/session", "local web draft")
        self.write("logs/main.log", "old login log")
        self.write("ant-did", "not-a-real-device-id")
        self.write("Login Data", "not-a-real-password-database")
        self.write("claude_desktop_config.json", '{"mcpServers":{"example":{"command":"example"}}}')
        self.write("git-worktrees.json", '{"worktrees":["fixture-worktree"]}')
        self.write("Local State", '{"os_crypt":{"encrypted_key":"fixture-key"}}')
        self.write("Preferences", '{"appearance":"dark"}')
        self.write("worktrees/my-project/notes.txt", "keep my work")
        self.write("custom-document.md", "keep my document")
        self.write(
            "config.json",
            json.dumps(
                {
                    "windowSizeWasSignedIn": True,
                    "planUsageLastTrayOpenAt": 123,
                    "locale": "zh-CN",
                    "windowBounds": {"width": 1000, "height": 700},
                    "unrelatedFeature": ["keep", "me"],
                }
            ),
        )

    @contextlib.contextmanager
    def main_environment(self, *arguments):
        with (
            mock.patch.object(sys, "argv", [str(SCRIPT), *map(str, arguments)]),
            mock.patch.object(cleanup, "discover", return_value=([], [self.root])) as discover,
            mock.patch.object(cleanup, "assert_closed") as closed,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            yield output, discover, closed

    def make_wal_snapshot_without_shm(self, count=2):
        """Copy a committed WAL fixture, then close its writer before testing."""
        writer_path = self.base / "fixture-writer.sqlite"
        connection = sqlite3.connect(writer_path)
        try:
            self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute("CREATE TABLE cookies (value TEXT)")
            connection.executemany("INSERT INTO cookies VALUES (?)", [("fixture",)] * count)
            connection.commit()
            destination = self.root / "Network" / "Cookies"
            destination.parent.mkdir()
            shutil.copy2(writer_path, destination)
            shutil.copy2(Path(str(writer_path) + "-wal"), Path(str(destination) + "-wal"))
        finally:
            connection.close()
        self.assertFalse(Path(str(destination) + "-shm").exists())
        return destination

    def test_inventory_is_read_only_and_counts_both_cookie_stores(self):
        self.populate()
        before = self.snapshot()
        result = cleanup.clean_owned_root(self.root, [self.root])
        self.assertFalse(result["applied"])
        self.assertEqual(result["cookies_before"], 4)
        self.assertIn("Network", result["selected_entries"])
        self.assertIn("Cache", result["selected_entries"])
        self.assertEqual(set(result["preserved_config_files"]), set(cleanup.PRESERVE))
        self.assertEqual(self.snapshot(), before)

    def test_apply_clears_auth_and_cache_but_preserves_configuration_and_work(self):
        self.populate()
        preserved = {name: (self.root / name).read_bytes() for name in cleanup.PRESERVE}
        result = cleanup.clean_owned_root(self.root, [self.root], apply=True)
        self.assertEqual(result["cookies_before"], 4)
        self.assertEqual(result["cookies_after"], 0)
        self.assertTrue(result["preserved_files_verified"])
        self.assertEqual(result["remaining_selected_entries"], [])
        for name in (*cleanup.STORES, *cleanup.FILES):
            self.assertFalse((self.root / name).exists(), name)
        for name, content in preserved.items():
            self.assertEqual((self.root / name).read_bytes(), content, name)
        self.assertEqual((self.root / "worktrees/my-project/notes.txt").read_text(), "keep my work")
        self.assertEqual((self.root / "custom-document.md").read_text(), "keep my document")
        self.assertEqual(
            json.loads((self.root / "config.json").read_text()),
            {"locale": "zh-CN", "windowBounds": {"width": 1000, "height": 700}, "unrelatedFeature": ["keep", "me"]},
        )

    def test_apply_is_idempotent(self):
        self.populate()
        cleanup.clean_owned_root(self.root, [self.root], apply=True)
        after_first = self.snapshot()
        second = cleanup.clean_owned_root(self.root, [self.root], apply=True)
        self.assertEqual(second["cookies_before"], 0)
        self.assertEqual(second["cookies_after"], 0)
        self.assertEqual(second["selected_entries"], [])
        self.assertEqual(second["login_ui_keys_selected"], [])
        self.assertEqual(self.snapshot(), after_first)

    def test_modern_oauth_and_device_records_are_removed_without_exposing_values(self):
        self.populate()
        config=json.loads((self.root/'config.json').read_text())
        config.update({'lastKnownAccountUuid':'fixture-account',
            'oauth:tokenCache':{'secret':'fixture-auth-do-not-report'},
            'oauth:tokenCacheV2':'fixture-auth-do-not-report',
            'unrelatedTokenPreference':'keep'})
        self.write('config.json',json.dumps(config))
        self.write('ant-device-registry.json','{"fixture":"fixture-auth-do-not-report"}')
        self.write('plan-usage-history.json','{"samples":["fixture"]}')
        self.write('claude-code-sessions/keep.txt','user work')
        self.write('local-agent-mode-sessions/keep.txt','cowork work')
        report=cleanup.clean_owned_root(self.root,[self.root],True)
        after=json.loads((self.root/'config.json').read_text())
        self.assertFalse(set(cleanup.CONFIG_LOGIN_KEYS)&set(after))
        self.assertEqual(after['unrelatedTokenPreference'],'keep')
        self.assertEqual(report['login_ui_keys_remaining'],[])
        self.assertTrue(report['normal_config_verified'])
        self.assertNotIn('fixture-auth-do-not-report',json.dumps(report))
        for name in ('ant-device-registry.json','plan-usage-history.json'):self.assertFalse((self.root/name).exists())
        self.assertEqual((self.root/'claude-code-sessions/keep.txt').read_text(),'user work')
        self.assertEqual((self.root/'local-agent-mode-sessions/keep.txt').read_text(),'cowork work')

    def test_discovery_includes_modern_and_legacy_roots_only_for_installed_family(self):
        local=self.base/'Local';roaming=self.base/'Roaming'
        modern=local/'Claude-Data/claude_pzs8sxrjxfjjc'
        legacy=local/'Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude'
        foreign=local/'Claude-Data/not-claude'
        for p in (modern,legacy,foreign):p.mkdir(parents=True)
        package={'PackageFamilyName':'Claude_pzs8sxrjxfjjc'}
        self.assertEqual(set(cleanup.discover_roots([package],local,roaming)),{modern,legacy})
        self.assertEqual(cleanup.discover_roots([],local,roaming),[])
        self.assertEqual(cleanup.discover_roots([{'PackageFamilyName':'not-claude'}],local,roaming),[])

    def test_all_discovered_cleans_modern_and_legacy_after_prevalidation(self):
        self.populate();second=self.base/'second';second.mkdir()
        (second/'ant-did').write_text('fixture')
        with self.main_environment('--all-discovered','--apply') as (output,discover,_):
            discover.return_value=([],[self.root,second]);cleanup.main()
        result=json.loads(output.getvalue())
        self.assertEqual(len(result['profiles']),2)
        self.assertTrue(all(p['cookies_after']==0 for p in result['profiles']))
        self.assertFalse((second/'ant-did').exists())

    def test_all_roots_prevalidated_before_first_deletion(self):
        self.populate();second=self.base/'second';(second/'Network').mkdir(parents=True)
        (second/'Network/Cookies').write_bytes(b'invalid database')
        before=self.snapshot()
        with self.main_environment('--all-discovered','--apply') as (_,discover,_):
            discover.return_value=([],[self.root,second])
            with self.assertRaises(sqlite3.DatabaseError):cleanup.main()
        self.assertEqual(self.snapshot(),before)

    def test_apply_all_without_known_roots_is_not_silent_success(self):
        with self.main_environment('--all-discovered','--apply') as (_,discover,_):
            discover.return_value=([],[])
            with self.assertRaisesRegex(RuntimeError,'No known Claude data roots'):cleanup.main()

    def test_redirected_configuration_refused_before_cleanup(self):
        self.write('Cache/keep','unchanged');outside=self.base/'external-config';outside.mkdir()
        (outside/'data').write_text('unchanged')
        self.make_directory_redirect(self.root/'config.json',outside)
        with self.assertRaisesRegex(RuntimeError,'redirected|Reparse/symlink'):
            cleanup.clean_owned_root(self.root,[self.root],True)
        self.assertEqual((self.root/'Cache/keep').read_text(),'unchanged')
        self.assertEqual((outside/'data').read_text(),'unchanged')

    def test_unknown_cookie_schema_refuses_before_any_deletion(self):
        self.make_cookies(recognized=False)
        self.write("Cache/keep-if-refused", "must survive")
        self.write("config.json", '{"windowSizeWasSignedIn":true,"locale":"en"}')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "Unrecognized Cookies database"):
            cleanup.clean_owned_root(self.root, [self.root], apply=True)
        self.assertEqual(self.snapshot(), before)

    def test_corrupt_cookie_database_refuses_before_any_deletion(self):
        self.write("Network/Cookies", b"this is not a SQLite database")
        self.write("Cache/keep-if-refused", "must survive")
        before = self.snapshot()
        with self.assertRaises(sqlite3.DatabaseError):
            cleanup.clean_owned_root(self.root, [self.root], apply=True)
        self.assertEqual(self.snapshot(), before)

    def test_unrecognized_config_shape_refuses_before_deletion(self):
        self.write("config.json", "[]")
        self.write("Cache/keep-if-refused", "must survive")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "Unsupported application configuration"):
            cleanup.clean_owned_root(self.root, [self.root], apply=True)
        self.assertEqual(self.snapshot(), before)

    def test_root_outside_discovered_roots_is_refused(self):
        self.populate()
        other = self.base / "OtherClaude"
        other.mkdir()
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "not one of the discovered"):
            cleanup.clean_owned_root(self.root, [other], apply=True)
        self.assertEqual(self.snapshot(), before)

    def test_relative_root_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "exact absolute"):
            cleanup.clean_owned_root(Path("Claude"), [self.root], apply=True)

    def make_directory_redirect(self, link, target):
        # Both endpoints must remain inside this disposable fixture. In
        # particular, never create a junction to a real application profile.
        self.assertTrue(link.is_absolute() and target.is_absolute())
        self.assertTrue(link.parent.resolve(strict=True).is_relative_to(self.base))
        self.assertTrue(target.resolve(strict=True).is_relative_to(self.base))
        self.assertFalse(link.exists() or link.is_symlink())
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            if os.name != "nt":
                self.skipTest(f"Directory symlinks unavailable: {error}")
            # Directory junctions do not require Windows symlink privileges.
            # Pass paths through child-only environment values rather than
            # interpolated code, and do not change PowerShell execution policy.
            environment = dict(os.environ)
            environment["CLAUDE_TEST_JUNCTION_LINK"] = str(link)
            environment["CLAUDE_TEST_JUNCTION_TARGET"] = str(target)
            try:
                subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                     "New-Item -ItemType Junction -Path $env:CLAUDE_TEST_JUNCTION_LINK "
                     "-Target $env:CLAUDE_TEST_JUNCTION_TARGET -ErrorAction Stop | Out-Null"],
                    capture_output=True, check=True, timeout=15,
                    env=environment,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.SubprocessError) as junction_error:
                self.fail(f"Neither symlink nor fixture junction could be created: {junction_error}")
        self.assertNotEqual(link.resolve(strict=True), link.absolute())

    def test_redirected_cleanup_store_is_refused_without_touching_target(self):
        outside = self.base / "unrelated-directory"
        outside.mkdir()
        (outside / "must-survive.txt").write_text("keep", encoding="utf-8")
        self.make_directory_redirect(self.root / "Cache", outside)
        with self.assertRaisesRegex(RuntimeError, "non-redirected|Reparse/symlink"):
            cleanup.clean_owned_root(self.root, [self.root], apply=True)
        self.assertNotEqual((self.root / "Cache").resolve(strict=True), (self.root / "Cache").absolute())
        self.assertEqual((outside / "must-survive.txt").read_text(), "keep")

    def test_nested_redirect_is_refused_before_any_selected_store_is_deleted(self):
        self.write("Network/ordinary-file", "must survive")
        self.write("Cache/ordinary-file", "must also survive")
        outside = self.base / "unrelated-directory"
        outside.mkdir()
        (outside / "must-survive.txt").write_text("keep", encoding="utf-8")
        self.make_directory_redirect(self.root / "Cache" / "redirect", outside)
        with self.assertRaisesRegex(RuntimeError, "Reparse/symlink"):
            cleanup.clean_owned_root(self.root, [self.root], apply=True)
        self.assertTrue((self.root / "Network/ordinary-file").is_file())
        self.assertTrue((self.root / "Cache/ordinary-file").is_file())
        self.assertEqual((outside / "must-survive.txt").read_text(), "keep")

    def test_redirected_root_is_refused(self):
        self.write("Cache/file", "keep")
        alias = self.base / "Alias"
        self.make_directory_redirect(alias, self.root)
        with self.assertRaisesRegex(RuntimeError, "non-redirected"):
            cleanup.clean_owned_root(alias, [self.root], apply=True)
        self.assertEqual((self.root / "Cache/file").read_text(), "keep")

    def test_temporary_directory_cleanup_removes_redirect_without_following_target(self):
        outside = self.base / "redirect-target"
        outside.mkdir()
        sentinel = outside / "must-survive.txt"
        sentinel.write_text("keep", encoding="utf-8")
        # The target is inside the overall fixture but outside the nested
        # TemporaryDirectory. Its cleanup must remove only the redirect.
        with tempfile.TemporaryDirectory(prefix="redirect-owner-", dir=self.base) as nested:
            nested_root = Path(nested).resolve()
            self.make_directory_redirect(nested_root / "redirect", outside)
        self.assertFalse(nested_root.exists())
        self.assertEqual(sentinel.read_text(), "keep")

    def test_wal_count_uses_disposable_copy_without_creating_source_shm(self):
        database = self.make_wal_snapshot_without_shm(count=2)
        before = self.snapshot()
        temporary_copies = []
        real_temporary_directory = tempfile.TemporaryDirectory

        def tracked_temporary_directory(*args, **kwargs):
            kwargs["dir"] = self.base
            directory = real_temporary_directory(*args, **kwargs)
            temporary_copies.append(Path(directory.name))
            return directory

        with mock.patch.object(cleanup.tempfile, "TemporaryDirectory", side_effect=tracked_temporary_directory):
            self.assertEqual(cleanup.cookie_count(self.root), 2)
        self.assertTrue(temporary_copies)
        self.assertTrue(all(not path.exists() for path in temporary_copies))
        self.assertFalse(Path(str(database) + "-shm").exists())
        self.assertEqual(self.snapshot(), before)

    def test_apply_removes_committed_wal_cookie_fixture(self):
        self.make_wal_snapshot_without_shm(count=2)
        result = cleanup.clean_owned_root(self.root, [self.root], apply=True)
        self.assertEqual(result["cookies_before"], 2)
        self.assertEqual(result["cookies_after"], 0)
        self.assertFalse((self.root / "Network").exists())

    def test_main_inventory_defaults_to_read_only(self):
        self.populate()
        before = self.snapshot()
        with self.main_environment() as (output, discover, closed):
            cleanup.main()
        result = json.loads(output.getvalue())
        self.assertFalse(result["applied"])
        self.assertEqual(result["profiles"][0]["cookies_before"], 4)
        discover.assert_called_once_with()
        closed.assert_called_once_with()
        self.assertEqual(self.snapshot(), before)

    def test_main_apply_requires_explicit_root(self):
        with self.main_environment("--apply") as (_, _, closed):
            with self.assertRaisesRegex(RuntimeError, "requires --root"):
                cleanup.main()
        closed.assert_not_called()

    def test_main_refuses_existing_report_without_overwriting_or_cleaning(self):
        self.populate()
        report = self.base / "existing-report.json"
        report.write_text("previous report", encoding="utf-8")
        before = self.snapshot()
        with self.main_environment("--apply", "--root", self.root, "--report", report):
            with self.assertRaisesRegex(RuntimeError, "Report already exists"):
                cleanup.main()
        self.assertEqual(report.read_text(), "previous report")
        self.assertEqual(self.snapshot(), before)

    def test_main_refuses_report_inside_claude_root_before_cleaning(self):
        self.populate()
        before = self.snapshot()
        report = self.root / "nested" / "report.json"
        with self.main_environment("--apply", "--root", self.root, "--report", report):
            with self.assertRaisesRegex(RuntimeError, "outside all Claude data roots"):
                cleanup.main()
        self.assertFalse(report.parent.exists())
        self.assertEqual(self.snapshot(), before)

    def test_main_creates_new_external_report_without_authentication_contents(self):
        self.populate()
        report = self.base / "new-report.json"
        with self.main_environment("--root", self.root, "--report", report) as (output, _, _):
            cleanup.main()
        self.assertEqual(json.loads(report.read_text(encoding="utf-8")), json.loads(output.getvalue()))
        report_text = report.read_text(encoding="utf-8")
        self.assertNotIn("not-a-real-cookie", report_text)
        self.assertNotIn("fixture-key", report_text)
        self.assertNotIn("keep my document", report_text)

    def test_main_failure_report_does_not_include_cookie_values_or_exception_details(self):
        self.make_cookies(recognized=False)
        self.write("Cache/file", "must survive")
        report = self.base / "failure-report.json"
        with self.main_environment("--apply", "--root", self.root, "--report", report):
            with self.assertRaisesRegex(RuntimeError, "Unrecognized Cookies database"):
                cleanup.main()
        result = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(result, {"outcome": "failed_possibly_partial", "profiles_completed": [], "error_type": "RuntimeError"})
        self.assertEqual((self.root / "Cache/file").read_text(), "must survive")


if __name__ == "__main__":
    unittest.main()
