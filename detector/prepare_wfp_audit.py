"""Build a version-pinned READ-ONLY reader for an already deployed guard.

Compiles source and runs offline comparison self-tests only. No WFP installation,
network start, UAC, registry or application changes. Never copies author reports.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys

import wfp_audit as audit

HERE = Path(__file__).resolve().parent


def prepare(root, inventory):
    root = audit.physical(Path(root), Path(root))
    if not (root/'installed.json').is_file():
        raise ValueError('existing_deployment_required')
    inventory = Path(inventory)
    audit.physical(inventory, inventory.parent)
    raw = inventory.read_bytes()
    if not 0 < len(raw) <= 16384:
        raise ValueError('inventory_size_invalid')
    value = json.loads(raw)
    package = value.get('package', '')
    family = 'Claude_pzs8sxrjxfjjc'
    rows = value.get('executables')
    if (value.get('schema') != 1 or value.get('family') != family
            or not re.fullmatch(r'Claude_[0-9.]+_x64__pzs8sxrjxfjjc', package)
            or type(rows) is not list or not 1 <= len(rows) <= 128
            or value.get('executable_count') != len(rows)):
        raise ValueError('inventory_invalid')
    mains = [Path(row.get('path', '')) for row in rows if type(row) is dict and Path(row.get('path', '')).name.lower() == 'claude.exe']
    if len(mains) != 1:
        raise ValueError('unique_main_image_required')
    app_root = mains[0].parent
    if app_root.name.lower() != 'app' or app_root.parent.name != package:
        raise ValueError('msix_application_layout_required')
    seen = set()
    for row in rows:
        path = audit.physical(Path(row['path']), app_root)
        key = str(path).casefold()
        if path.suffix.lower() != '.exe' or key in seen or audit.sha(path) != row['sha256']:
            raise ValueError('inventory_identity_changed')
        seen.add(key)
    folder = root/'maintenance'
    folder.mkdir(exist_ok=True)
    audit.physical(folder, root)
    target = folder/('readonly-wfp-'+secrets.token_hex(8))
    target.mkdir()
    pinned = target/'inventory.json'; pinned.write_bytes(raw)
    text = (HERE/'native/DetailedWfpReadOnly.cs.in').read_text('utf8')
    replacements = {'INVENTORY': str(pinned).replace('"','""'), 'INVENTORY_HASH': audit.sha(pinned),
                    'PACKAGE': package, 'APP_ROOT': str(app_root).replace('"','""'), 'EXECUTABLE_COUNT': str(len(rows))}
    for key, item in replacements.items(): text = text.replace('@@'+key+'@@', item)
    if '@@' in text: raise ValueError('reader_template_invalid')
    source = target/'DetailedWfpReadOnly.cs'; source.write_text(text, 'utf8')
    executable = target/'DetailedWfpReadOnly.exe'
    compiler = Path(os.environ.get('WINDIR', r'C:\Windows'))/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    command = [str(compiler), '/nologo', '/platform:x64', '/target:exe', '/r:System.Web.Extensions.dll', '/out:'+str(executable), str(source)]
    built = subprocess.run(command, capture_output=True, timeout=60)
    if built.returncode: raise ValueError('reader_build_failed')
    checked = subprocess.run([str(executable), '--self-test'], capture_output=True, text=True, timeout=15)
    result = json.loads(checked.stdout)
    if checked.returncode or result.get('passed') is not True:
        raise ValueError('reader_self_test_failed')
    manifest = dict(schema=1, reader=executable.relative_to(root).as_posix(), reader_sha256=audit.sha(executable),
                    inventory=pinned.relative_to(root).as_posix(), inventory_sha256=audit.sha(pinned),
                    package=package, family=family, executable_count=len(rows), scope_count=len(rows)+1, filter_count=(len(rows)+1)*4)
    destination = root/'detector'
    destination.mkdir(exist_ok=True); audit.physical(destination, root)
    # No overwrite of an existing binding. Rebind only after reviewing a version update.
    with (destination/'wfp-audit.json').open('x', encoding='utf8') as handle:
        json.dump(manifest, handle, indent=2)
    return dict(prepared=True, read_only=True, rules_modified=False, packet_enforcement_tested=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.root, args.inventory)))
        return 0
    except Exception:
        print(json.dumps(dict(prepared=False, error='audit_preparation_failed_review_locally', rules_modified=False)))
        return 2


if __name__ == '__main__': sys.exit(main())
