"""Synthetic fixtures only: never start, stop or inspect a live Claude instance."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "launch_preflight.py"
SPEC = importlib.util.spec_from_file_location("launch_preflight", MODULE_PATH)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)

PORT = 18080
PACKAGE = "Claude_1.2.3.4_x64__examplepublisher"
ROOT = r"C:\Program Files\WindowsApps\Claude_1.2.3.4_x64__examplepublisher"
EXE = ROOT + r"\app\Claude.exe"
FLAGS = ["--proxy-server=http://127.0.0.1:18080", "--proxy-bypass-list=<-loopback>", "--disable-quic"]
MARKER = {"schema_version": 1, "package_full_name": PACKAGE, "gateway_port": PORT}


def row(arguments=None, pid=1234, executable=EXE):
    return {"ProcessId": pid, "ExecutablePath": executable,
            "CommandLine": json.dumps([executable] + (FLAGS if arguments is None else arguments))}


def snapshot(processes=None):
    return {"packages": [{"PackageFullName": PACKAGE, "Version": "1.2.3.4", "InstallLocation": ROOT}],
            "candidate_exists": True, "gateway_listening": True,
            "processes": [row()] if processes is None else processes}


class LaunchPreflightTests(unittest.TestCase):
    def evaluate(self, state=None, marker=MARKER):
        return preflight.evaluate(state if state is not None else snapshot(), PORT, marker, json.loads)

    def test_matches_never_claim_enforcement(self):
        report = self.evaluate()
        self.assertEqual(report["status"], "preflight_checks_passed")
        self.assertFalse(report["protection_verified"])
        self.assertIn("not prove", " ".join(report["limits"]))

    def test_no_marker_requires_review(self):
        self.assertEqual(self.evaluate(marker=None)["status"], "needs_review")

    def test_no_main_requires_review(self):
        self.assertEqual(self.evaluate(snapshot([]))["status"], "needs_review")

    def test_electron_children_are_ignored(self):
        state = snapshot([row(), row(["--type=renderer"], 1235), row(["--type=gpu-process"], 1236)])
        self.assertEqual(self.evaluate(state)["main_processes"], [{"pid": 1234, "flags": "match"}])

    def test_invalid_child_type_is_not_silently_ignored(self):
        for flags in (["--type"], ["--type="], ["--type=renderer", "--type=utility"],
                      ["--TYPE=renderer"], ["--Type=utility"], ["--type=Renderer"],
                      ["--type=unknown"], FLAGS + ["--TYPE=renderer"],
                      ["--type=renderer", "--TYPE=utility"]):
            with self.subTest(flags=flags):
                self.assertEqual(self.evaluate(snapshot([row(flags)]))["error"], "unclassifiable_claude_process")

    def test_bare_main_is_rejected(self):
        self.assertEqual(self.evaluate(snapshot([row([])]))["error"], "existing_main_process_proxy_flags_mismatch")

    def test_multiple_mains_all_must_match(self):
        self.assertEqual(self.evaluate(snapshot([row(), row([], 4321)]))["status"], "blocked")

    def test_missing_required_switches(self):
        for index in range(len(FLAGS)):
            with self.subTest(index=index):
                self.assertEqual(self.evaluate(snapshot([row(FLAGS[:index] + FLAGS[index + 1:])]))["status"], "blocked")

    def test_duplicate_and_conflicting_switches(self):
        for extra in FLAGS + ["--proxy-server=http://127.0.0.1:9999", "--proxy-server", "--proxy-bypass-list",
                              "--disable-quic=false", "--no-proxy-server", "--proxy-auto-detect",
                              "--proxy-pac-url=https://example.invalid/pac"]:
            with self.subTest(extra=extra):
                self.assertEqual(self.evaluate(snapshot([row(FLAGS + [extra])]))["status"], "blocked")

    def test_mixed_case_duplicate_and_conflicting_switch_keys(self):
        for extra in ("--PROXY-SERVER=http://127.0.0.1:9999", "--PROXY-SERVER=http://127.0.0.1:18080",
                      "--Proxy-Server", "--PROXY-BYPASS-LIST=<-loopback>", "--DISABLE-QUIC",
                      "--NO-PROXY-SERVER", "--No-Proxy-Server=false", "--PROXY-AUTO-DETECT",
                      "--Proxy-Pac-Url=https://example.invalid/pac"):
            with self.subTest(extra=extra):
                self.assertEqual(self.evaluate(snapshot([row(FLAGS + [extra])]))["status"], "blocked")

    def test_noncanonical_required_switch_keys_are_ambiguous(self):
        for index in range(len(FLAGS)):
            modified = list(FLAGS)
            key, separator, value = modified[index].partition("=")
            modified[index] = key.upper() + separator + value
            with self.subTest(index=index):
                self.assertEqual(self.evaluate(snapshot([row(modified)]))["status"], "blocked")

    def test_required_switch_values_are_not_case_normalized(self):
        for changed in ("--proxy-server=HTTP://127.0.0.1:18080", "--proxy-bypass-list=<-LOOPBACK>"):
            modified = [flag for flag in FLAGS if flag.partition("=")[0] != changed.partition("=")[0]] + [changed]
            with self.subTest(changed=changed):
                self.assertEqual(self.evaluate(snapshot([row(modified)]))["status"], "blocked")

    def test_wrong_host_or_port_or_scheme(self):
        for flag in ("--proxy-server=http://localhost:18080", "--proxy-server=http://127.0.0.1:9999",
                     "--proxy-server=socks5://127.0.0.1:18080"):
            with self.subTest(flag=flag):
                self.assertEqual(self.evaluate(snapshot([row([flag] + FLAGS[1:])]))["status"], "blocked")

    def test_flags_after_separator_do_not_count(self):
        self.assertEqual(self.evaluate(snapshot([row(["--"] + FLAGS)]))["status"], "blocked")
        self.assertEqual(self.evaluate(snapshot([row(FLAGS + ["--", "--no-proxy-server"])]))["status"], "preflight_checks_passed")

    def test_old_or_unknown_installation_is_rejected(self):
        state = snapshot([row(executable=r"C:\Other\Claude.exe")])
        self.assertEqual(self.evaluate(state)["error"], "claude_process_outside_current_package")

    def test_process_snapshot_validation(self):
        for invalid in (None, {}, "private", [None], [dict(row(), ExecutablePath=None)],
                        [dict(row(), ProcessId=True)], [dict(row(), ProcessId=0)]):
            with self.subTest(invalid_type=type(invalid).__name__):
                state = snapshot()
                state["processes"] = invalid
                self.assertEqual(self.evaluate(state)["status"], "blocked")

    def test_argv_executable_must_match(self):
        state = snapshot()
        state["processes"][0]["CommandLine"] = json.dumps([r"C:\Other\Claude.exe"] + FLAGS)
        self.assertEqual(self.evaluate(state)["error"], "process_executable_mismatch")

    def test_path_case_and_dot_normalization(self):
        state = snapshot([row(executable=ROOT.lower() + r"\app\.\CLAUDE.EXE")])
        self.assertEqual(self.evaluate(state)["status"], "preflight_checks_passed")

    def test_marker_mismatch_is_blocked(self):
        for changes in ({"package_full_name": PACKAGE.replace("1.2.3.4", "1.2.3.5")}, {"gateway_port": 18081}):
            with self.subTest(changes=changes):
                self.assertEqual(self.evaluate(marker=dict(MARKER, **changes))["error"], "marker_package_or_port_mismatch")

    def test_marker_rejects_legacy_and_unknown_schema(self):
        invalid = [{"package": PACKAGE}, dict(MARKER, extra=True), dict(MARKER, schema_version=2),
                   dict(MARKER, schema_version=True), dict(MARKER, gateway_port=True),
                   dict(MARKER, gateway_port=0), dict(MARKER, gateway_port=65536),
                   dict(MARKER, package_full_name=""), []]
        for marker in invalid:
            with self.subTest(marker=marker):
                self.assertEqual(self.evaluate(marker=marker)["status"], "blocked")

    def test_package_missing_ambiguous_or_malformed(self):
        for packages in ([], [None], [snapshot()["packages"][0]] * 2,
                         [{"PackageFullName": PACKAGE}], "not-a-list"):
            with self.subTest(packages=packages):
                state = snapshot()
                state["packages"] = packages
                self.assertEqual(self.evaluate(state)["status"], "blocked")

    def test_invalid_version_is_not_echoed(self):
        state = snapshot()
        state["packages"][0]["Version"] = "PRIVATE_UNEXPECTED_VERSION_DATA"
        report = self.evaluate(state)
        self.assertEqual(report["error"], "invalid_package_version")
        self.assertNotIn("PRIVATE_UNEXPECTED", json.dumps(report))

    def test_missing_executable_is_rejected(self):
        state = snapshot()
        state["candidate_exists"] = False
        self.assertEqual(self.evaluate(state)["error"], "claude_executable_not_found")

    def test_listener_absent_or_unknown_is_blocked(self):
        for listening in (False, None, "true", 1):
            with self.subTest(listening=listening):
                state = snapshot()
                state["gateway_listening"] = listening
                self.assertEqual(self.evaluate(state)["status"], "blocked")

    def test_report_does_not_echo_process_arguments_or_paths(self):
        secret = "EXAMPLE_SECRET_NOT_FOR_OUTPUT"
        state = snapshot([row(FLAGS + ["--unrelated=" + secret])])
        serialized = json.dumps(self.evaluate(state))
        self.assertNotIn(secret, serialized)
        self.assertNotIn(ROOT, serialized)
        self.assertNotIn("CommandLine", serialized)

    def test_marker_file_is_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "marker.json"
            data = json.dumps(MARKER).encode("utf-8")
            path.write_bytes(data)
            self.assertEqual(preflight.load_marker(path), MARKER)
            self.assertEqual(path.read_bytes(), data)

    def test_marker_file_failure_and_size_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "marker.json"
            for data in (b"{", b"x" * 17000):
                path.write_bytes(data)
                with self.assertRaises(preflight.CheckError):
                    preflight.load_marker(path)
            with self.assertRaises(preflight.CheckError):
                preflight.load_marker(Path(temp) / "absent.json")

    def test_duplicate_json_marker_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "marker.json"
            path.write_text(json.dumps(MARKER)[:-1] + ',"gateway_port":18081}', encoding="utf-8")
            with self.assertRaisesRegex(preflight.CheckError, "duplicate_json_key"):
                preflight.load_marker(path)

    def test_gateway_port_validation(self):
        self.assertEqual(preflight.gateway_port("18080"), PORT)
        for value in ("0", "65536", "abc", "18080; exit"):
            with self.subTest(value=value), self.assertRaises(Exception):
                preflight.gateway_port(value)

    def test_help_does_not_query_or_modify(self):
        with mock.patch.object(preflight, "query_windows") as query, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                preflight.main(["--help"])
            self.assertEqual(caught.exception.code, 0)
            query.assert_not_called()

    def test_gateway_port_is_mandatory(self):
        with mock.patch.object(preflight, "query_windows") as query, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                preflight.main([])
            self.assertEqual(caught.exception.code, 2)
            query.assert_not_called()

    def test_query_failure_is_not_reported_as_success(self):
        output = io.StringIO()
        with mock.patch.object(preflight, "query_windows", side_effect=preflight.CheckError("windows_query_failed")), contextlib.redirect_stdout(output):
            code = preflight.main(["--gateway-port", str(PORT)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "blocked")

    def test_unexpected_exception_is_sanitized(self):
        output = io.StringIO()
        secret = "PRIVATE_COMMAND_LINE"
        with mock.patch.object(preflight, "query_windows", side_effect=ValueError(secret)), contextlib.redirect_stdout(output):
            code = preflight.main(["--gateway-port", str(PORT)])
        self.assertEqual(code, 2)
        self.assertNotIn(secret, output.getvalue())

    @unittest.skipUnless(os.name == "nt", "Windows subprocess adapter test; subprocess is mocked")
    def test_windows_query_adapter_never_prints_failed_output(self):
        fake = subprocess.CompletedProcess([], 1, "PRIVATE_STDOUT", "PRIVATE_STDERR")
        with mock.patch.object(preflight.subprocess, "run", return_value=fake) as run:
            with self.assertRaisesRegex(preflight.CheckError, "^windows_query_failed$"):
                preflight.query_windows(PORT)
        self.assertEqual(run.call_args.kwargs["timeout"], 20)
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    @unittest.skipUnless(os.name == "nt", "Windows subprocess adapter test; subprocess is mocked")
    def test_windows_query_adapter_rejects_partial_or_malformed_output(self):
        for payload in ("not-json", "[]", '{"packages":[],"packages":[]}'):
            with self.subTest(payload=payload), mock.patch.object(preflight.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, payload, "")):
                with self.assertRaises(preflight.CheckError):
                    preflight.query_windows(PORT)

    @unittest.skipUnless(os.name == "nt", "Windows subprocess adapter test; subprocess is mocked")
    def test_windows_query_adapter_returns_snapshot_without_side_effects(self):
        state = snapshot()
        with mock.patch.object(preflight.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(state), "")) as run:
            self.assertEqual(preflight.query_windows(PORT), state)
        command = run.call_args.args[0]
        self.assertEqual(command[0], "powershell.exe")
        self.assertIn("-NoProfile", command)
        self.assertIn("$_.LocalPort -eq 18080", command[-1])
        for mutation in ("Stop-Process", "Start-Process", "Set-NetFirewall", "New-NetFirewall", "Remove-Item"):
            self.assertNotIn(mutation, command[-1])

    @unittest.skipUnless(os.name == "nt", "Windows API test")
    def test_native_windows_parser_preserves_quoted_executable(self):
        args = [EXE] + FLAGS + [r"--example=C:\a folder\file.txt", '--example-quote=a"b']
        self.assertEqual(preflight.windows_command_line_args(subprocess.list2cmdline(args)), args)

    @unittest.skipUnless(os.name == "nt", "Windows API test")
    def test_native_windows_parser_rejects_empty_and_nul(self):
        for value in (None, "", " ", "claude\0--proxy-server=x"):
            with self.subTest(value=value), self.assertRaises(preflight.CheckError):
                preflight.windows_command_line_args(value)


if __name__ == "__main__":
    unittest.main()
