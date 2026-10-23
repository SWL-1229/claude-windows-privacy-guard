#!/usr/bin/env python3
"""Read-only Claude/MSIX launch checks. This is not a guard installer.

No process is started/stopped; no firewall, proxy or login data is changed.
A listener and matching marker do not prove ownership, egress IP or WFP rules.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import ntpath
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable


class CheckError(Exception):
    """A stable error code, intentionally excluding private command output."""


def strict_json(text: str):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CheckError("duplicate_json_key")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique_object)


def gateway_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be in 1..65535")
    return port


def windows_command_line_args(command_line: str) -> list[str]:
    """Use the Windows API, never POSIX shlex or a hand-written approximation."""
    if os.name != "nt":
        raise CheckError("windows_required")
    if not isinstance(command_line, str) or not command_line.strip() or "\0" in command_line:
        raise CheckError("command_line_unavailable")
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    parse = shell32.CommandLineToArgvW
    parse.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    parse.restype = ctypes.POINTER(wintypes.LPWSTR)
    free = kernel32.LocalFree
    free.argtypes = [wintypes.HLOCAL]
    free.restype = wintypes.HLOCAL
    count = ctypes.c_int()
    argv = parse(command_line, ctypes.byref(count))
    if not argv:
        raise CheckError("command_line_parse_failed")
    try:
        return [argv[index] for index in range(count.value)]
    finally:
        free(ctypes.cast(argv, wintypes.HLOCAL))


def query_windows(port: int) -> dict:
    """One bounded PowerShell query; raw stdout/stderr are never printed."""
    if os.name != "nt":
        raise CheckError("windows_required")
    # The sole interpolation is a validated integer, never a path or command line.
    if type(port) is not int or not 1 <= port <= 65535:
        raise CheckError("invalid_gateway_port")
    script = r"""$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$packages=@(Get-AppxPackage -Name Claude -ErrorAction Stop | Select-Object PackageFullName,Version,InstallLocation)
$processes=@(Get-CimInstance Win32_Process -Filter "Name='Claude.exe'" -ErrorAction Stop | Select-Object ProcessId,ExecutablePath,CommandLine)
$listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq PORT_VALUE -and ($_.LocalAddress -eq '127.0.0.1' -or $_.LocalAddress -eq '0.0.0.0') })
$candidateExists=$false
if ($packages.Count -eq 1) { $candidateExists=Test-Path -LiteralPath (Join-Path $packages[0].InstallLocation 'app\Claude.exe') -PathType Leaf }
@{packages=$packages;processes=$processes;gateway_listening=[bool]($listeners.Count -gt 0);candidate_exists=[bool]$candidateExists} | ConvertTo-Json -Depth 5 -Compress
""".replace("PORT_VALUE", str(port))
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, encoding="utf-8-sig", timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode:
            raise CheckError("windows_query_failed")
        snapshot = strict_json(result.stdout)
    except subprocess.TimeoutExpired:
        raise CheckError("windows_query_timed_out") from None
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise CheckError("windows_query_failed") from None
    if not isinstance(snapshot, dict):
        raise CheckError("invalid_windows_snapshot")
    return snapshot


def load_marker(path: Path) -> dict:
    """Accept only the documented minimal marker, not legacy/private formats."""
    try:
        if path.stat().st_size > 16384:
            raise CheckError("invalid_marker")
        marker = strict_json(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise CheckError("marker_unreadable") from None
    validate_marker(marker)
    return marker


def validate_marker(marker: dict) -> None:
    if not isinstance(marker, dict) or set(marker) != {"schema_version", "package_full_name", "gateway_port"}:
        raise CheckError("invalid_marker_schema")
    if type(marker["schema_version"]) is not int or marker["schema_version"] != 1:
        raise CheckError("unsupported_marker_schema")
    if not isinstance(marker["package_full_name"], str) or not marker["package_full_name"].strip():
        raise CheckError("invalid_marker_package")
    if type(marker["gateway_port"]) is not int or not 1 <= marker["gateway_port"] <= 65535:
        raise CheckError("invalid_marker_port")


def normalized_path(value: str) -> str:
    if not isinstance(value, str) or not ntpath.isabs(value) or "\0" in value:
        raise CheckError("process_path_unavailable")
    return ntpath.normcase(ntpath.normpath(value))


def check_main_flags(args: list[str], port: int) -> bool:
    # Chromium stops parsing switches at '--'. Flags after it are not protection.
    if "--" in args:
        args = args[:args.index("--")]
    required = {
        "--proxy-server": f"--proxy-server=http://127.0.0.1:{port}",
        "--proxy-bypass-list": "--proxy-bypass-list=<-loopback>",
        "--disable-quic": "--disable-quic",
    }
    # Count switch KEYS case-insensitively, while requiring the exact supported
    # spelling/value below. Do not assume every Chromium build treats mixed-case
    # keys identically; ambiguous duplicates must never pass this preflight.
    def switch_key(arg: str) -> str:
        return arg.partition("=")[0].lower()

    for flag, expected in required.items():
        matches = [arg for arg in args if switch_key(arg) == flag]
        if matches != [expected]:
            return False
    conflicting = ("--no-proxy-server", "--proxy-pac-url", "--proxy-auto-detect")
    return not any(switch_key(arg) in conflicting for arg in args)


def inspect_processes(rows: list, executable: str, port: int,
                      parser: Callable[[str], list[str]] = windows_command_line_args) -> list[dict]:
    if not isinstance(rows, list):
        raise CheckError("invalid_process_snapshot")
    expected = normalized_path(executable)
    mains = []
    for row in rows:
        if not isinstance(row, dict) or type(row.get("ProcessId")) is not int or row["ProcessId"] <= 0:
            raise CheckError("invalid_process_snapshot")
        # Unknown/older installations are deliberately not silently ignored.
        if normalized_path(row.get("ExecutablePath")) != expected:
            raise CheckError("claude_process_outside_current_package")
        argv = parser(row.get("CommandLine"))
        if not argv or not all(isinstance(arg, str) for arg in argv):
            raise CheckError("invalid_process_arguments")
        if normalized_path(argv[0]) != expected:
            raise CheckError("process_executable_mismatch")
        args = argv[1:]
        if "--" in args:
            args = args[:args.index("--")]
        types = [arg for arg in args if arg.partition("=")[0].lower() == "--type"]
        if types:
            # Only classify explicit, known child types. Mixed-case switch keys,
            # type values or unknown values are ambiguous and require review.
            child_types = {"renderer", "gpu-process", "utility", "zygote", "crashpad-handler", "ppapi", "ppapi-broker"}
            if (len(types) != 1 or not types[0].startswith("--type=")
                    or types[0].partition("=")[2] not in child_types):
                raise CheckError("unclassifiable_claude_process")
            continue
        mains.append({"pid": row["ProcessId"], "flags": "match" if check_main_flags(args, port) else "mismatch"})
    return mains


def evaluate(snapshot: dict, port: int, marker: dict | None = None,
             parser: Callable[[str], list[str]] = windows_command_line_args) -> dict:
    report = {
        "status": "blocked", "protection_verified": False, "checks": {},
        "limits": ["Read-only launch checks only; not an installer.",
                   "A listening port and matching marker do not prove gateway ownership, egress IP or WFP enforcement."],
    }
    try:
        packages = snapshot.get("packages")
        if not isinstance(packages, list) or len(packages) != 1:
            raise CheckError("claude_package_missing_or_ambiguous")
        package = packages[0]
        if not isinstance(package, dict) or not all(isinstance(package.get(key), str) and package[key].strip()
                                                   for key in ("PackageFullName", "Version", "InstallLocation")):
            raise CheckError("invalid_package_snapshot")
        if not re.fullmatch(r"\d{1,5}(?:\.\d{1,5}){3}", package["Version"]):
            raise CheckError("invalid_package_version")
        if snapshot.get("candidate_exists") is not True:
            raise CheckError("claude_executable_not_found")
        report["version"] = package["Version"]
        report["checks"]["package"] = "found"
        if marker is None:
            report["checks"]["marker_consistency"] = "not_provided"
        else:
            validate_marker(marker)
            if marker["package_full_name"] != package["PackageFullName"] or marker["gateway_port"] != port:
                raise CheckError("marker_package_or_port_mismatch")
            report["checks"]["marker_consistency"] = "match_not_proof_of_protection"
        if type(snapshot.get("gateway_listening")) is not bool:
            raise CheckError("invalid_listener_snapshot")
        report["checks"]["gateway_listener"] = "present_not_proof_of_identity" if snapshot["gateway_listening"] else "absent"
        if not snapshot["gateway_listening"]:
            raise CheckError("gateway_not_listening")
        executable = ntpath.join(package["InstallLocation"], "app", "Claude.exe")
        mains = inspect_processes(snapshot.get("processes"), executable, port, parser)
        report["main_processes"] = mains
        if any(row["flags"] != "match" for row in mains):
            raise CheckError("existing_main_process_proxy_flags_mismatch")
        report["checks"]["main_process_flags"] = "match" if mains else "not_running"
        report["status"] = "preflight_checks_passed" if marker is not None and mains else "needs_review"
    except CheckError as error:
        report["error"] = str(error)
    return report


def main(argv: list[str] | None = None) -> int:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--gateway-port", required=True, type=gateway_port,
                                 help="the dedicated IPv4 loopback guard port; no default")
    argument_parser.add_argument("--installed-marker", type=Path,
                                 help="optional schema v1 JSON marker, used only for package/port consistency")
    args = argument_parser.parse_args(argv)
    try:
        marker = load_marker(args.installed_marker) if args.installed_marker else None
        report = evaluate(query_windows(args.gateway_port), args.gateway_port, marker)
    except CheckError as error:
        report = {"status": "blocked", "protection_verified": False, "error": str(error)}
    except Exception:
        # Do not accidentally disclose raw process arguments or PowerShell output.
        report = {"status": "blocked", "protection_verified": False, "error": "unexpected_check_failure"}
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report["status"] == "preflight_checks_passed" else 2


if __name__ == "__main__":
    sys.exit(main())
