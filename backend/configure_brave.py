"""Prepare a LOCAL Brave binding in a fresh, held build. No launch or install."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

from configure import HOLD, physical


def signed_version(executable):
    # Fixed command; the path is data in the child environment, never PS code.
    script = "$ErrorActionPreference='Stop'; Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1'); " \
             "$p=$env:CLAUDE_BRAVE_BINDING_PATH; $s=Get-AuthenticodeSignature -LiteralPath $p; " \
             "$v=(Get-Item -LiteralPath $p).VersionInfo.FileVersion; " \
             "$n=if($s.SignerCertificate){$s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)}else{''}; " \
             "@{valid=($s.Status -eq 'Valid');publisher=$n;version=$v}|ConvertTo-Json -Compress"
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            env={**os.environ, 'CLAUDE_BRAVE_BINDING_PATH': str(executable)},
                            capture_output=True, text=True, encoding='utf8', errors='replace', timeout=30,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ValueError('brave_signature_query_failed')
    value = json.loads(result.stdout)
    if (value.get('valid') is not True
            or value.get('publisher') != 'Brave Software, Inc.'
            or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', str(value.get('version', '')).strip())):
        raise ValueError('official_brave_signature_required')
    return value['version'].strip()


def prepare(output):
    output = physical(str(output), True)
    if output.name.casefold() == '.claude-network-guard' or (output/'installed.json').exists():
        raise ValueError('live_installation_refused')
    if (output/'hold.block').read_text('ascii') != HOLD:
        raise ValueError('original_deployment_hold_required')
    if json.loads((output/'configured.json').read_text('utf8')).get('installed') is not False:
        raise ValueError('configured_uninstalled_build_required')
    executable = physical(str(Path(os.environ['LOCALAPPDATA'])/'BraveSoftware/Brave-Browser/Application/brave.exe'))
    before = executable.stat()
    version = signed_version(executable)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    after = executable.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('brave_changed_during_binding')
    value = dict(schema=1, browser_executable=str(executable), sha256=digest,
                 size=after.st_size, mtime_ns=after.st_mtime_ns,
                 version=version, publisher_verified=True)
    # Exclusive create: don't silently rebind an active/updated browser.
    with (output/'brave-runtime.json').open('x', encoding='utf8', newline='\n') as handle:
        json.dump(value, handle, indent=2)
    return dict(prepared=True, installed=False, network_started=False, deployment_hold_retained=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.output)))
        return 0
    except Exception:
        print(json.dumps(dict(prepared=False, installed=False, error='brave_binding_failed_review_locally')))
        return 2


if __name__ == '__main__':
    sys.exit(main())
