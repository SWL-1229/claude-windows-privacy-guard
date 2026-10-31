"""Read-only Windows layout discovery; never prints command lines or auth values.

Can run while Claude is open to identify the actual --user-data-dir. This is not
a login-store reader, a network probe, a guard installer or an approval to clean.
"""
from __future__ import annotations
import argparse,json,ntpath,os,subprocess,sys
from pathlib import Path
from desktop_cleanup import discover_roots
from launch_preflight import windows_command_line_args

def query_windows():
    if os.name!='nt':raise RuntimeError('windows_required')
    script=r'''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
@{packages=@(Get-AppxPackage -Name Claude -ErrorAction Stop | Select-Object Name,Version,PackageFamilyName,PackageFullName,InstallLocation);
processes=@(Get-CimInstance Win32_Process -Filter "Name='Claude.exe'" -ErrorAction Stop | Select-Object ProcessId,ExecutablePath,CommandLine)} | ConvertTo-Json -Compress -Depth 4'''
    p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,encoding='utf-8-sig',timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    if p.returncode:raise RuntimeError('windows_inventory_failed')
    value=json.loads(p.stdout)
    if not isinstance(value,dict):raise RuntimeError('inventory_format_invalid')
    return value

def describe_runtime(rows,expected_images,known_roots,parser=windows_command_line_args):
    """Return only target identity/layout fields; discard all other switches."""
    norm=lambda p:ntpath.normcase(ntpath.normpath(p))
    expected={norm(p) for p in expected_images};known={norm(str(p)) for p in known_roots}
    result=[]
    for row in rows:
        if (not isinstance(row,dict) or type(row.get('ProcessId')) is not int
                or row['ProcessId']<=0 or not isinstance(row.get('ExecutablePath'),str)
                or not ntpath.isabs(row['ExecutablePath'])):
            raise RuntimeError('process_identity_unavailable')
        image=row['ExecutablePath']
        if norm(image) not in expected:
            result.append({'pid':row['ProcessId'],'current_package_image':False,'layout':'needs_review'})
            continue
        args=parser(row.get('CommandLine'))
        if not args or norm(args[0])!=norm(image):raise RuntimeError('process_arguments_invalid')
        flags=args[1:args.index('--')] if '--' in args else args[1:]
        dirs=[a.split('=',1)[1] for a in flags if a.lower().startswith('--user-data-dir=')]
        if len(dirs)>1 or any(not ntpath.isabs(p) or '\0' in p for p in dirs):
            raise RuntimeError('runtime_data_directory_ambiguous')
        result.append({'pid':row['ProcessId'],'current_package_image':True,
            'user_data_dir':dirs[0] if dirs else None,
            'layout':'known' if dirs and norm(dirs[0]) in known else 'needs_review' if dirs else 'not_exposed'})
    return result

def build_report(snapshot,local,roaming,parser=windows_command_line_args):
    packages=snapshot.get('packages');rows=snapshot.get('processes')
    if not isinstance(packages,list) or not isinstance(rows,list):raise RuntimeError('inventory_format_invalid')
    roots=discover_roots(packages,local,roaming)
    images=[ntpath.join(p['InstallLocation'],'app','Claude.exe') for p in packages
            if isinstance(p.get('InstallLocation'),str) and ntpath.isabs(p['InstallLocation'])]
    runtime=describe_runtime(rows,images,roots,parser)
    return {'schema':1,'read_only':True,'protection_verified':False,
        'packages':[{k:p.get(k) for k in ('Version','PackageFullName','PackageFamilyName','InstallLocation')} for p in packages],
        'known_desktop_roots':[str(p) for p in roots], 'runtime_layout':runtime,
        'cleanup_ready':not rows and bool(roots),
        'review_needed':any(p['layout']=='needs_review' for p in runtime) or not roots or len(packages)!=1,
        'limits':['Known layouts only; closed apps may not expose a custom user-data-dir.',
                  'No cookies, tokens, browser records, network rules or account state were read or changed.',
                  'A runtime directory outside known roots requires manual review; do not add arbitrary deletion paths.']}

def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        report=build_report(query_windows(),os.environ['LOCALAPPDATA'],os.environ['APPDATA'])
        code=2 if report['review_needed'] else 0
    except Exception:
        report={'read_only':True,'protection_verified':False,'error':'layout_inventory_failed','review_needed':True};code=2
    print(json.dumps(report,ensure_ascii=True,indent=2));return code
if __name__=='__main__':sys.exit(main())
