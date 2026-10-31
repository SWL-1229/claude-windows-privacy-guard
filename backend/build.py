"""Build this source snapshot into a NEW directory. No install or activation.

No network, app launch, UAC, firewall, registry, profile or live-runtime changes.
Uses the Windows .NET Framework compiler already present on the build machine.
"""
from __future__ import annotations
import argparse,hashlib,json,os,shutil,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE=HERE/'source'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def fresh_destination(value):
    raw=Path(value)
    if not raw.is_absolute() or '..' in raw.parts:raise ValueError('absolute_new_output_required')
    if raw.exists() or raw.is_symlink():raise ValueError('output_exists_no_overwrite')
    parent=raw.parent.resolve(strict=True)
    if parent!=raw.parent.absolute():raise ValueError('redirected_output_parent')
    for p in (parent,*parent.parents):
        if p.is_symlink() or getattr(p.stat(),'st_file_attributes',0)&0x400:raise ValueError('redirected_output_parent')
    if raw.name.casefold()=='.claude-network-guard':raise ValueError('live_installation_destination_refused')
    if raw.is_relative_to(SOURCE):raise ValueError('output_inside_source_refused')
    return raw

def verify_source():
    manifest=json.loads((HERE/'source-manifest.json').read_text(encoding='utf8'))
    expected={r['path']:r['published_sha256'] for r in manifest['files']}
    for name,digest in expected.items():
        p=SOURCE/name
        if p.resolve(strict=True)!=p.absolute() or sha(p)!=digest:raise ValueError('source_manifest_mismatch')
    actual={str(p.relative_to(SOURCE)).replace('\\','/') for p in SOURCE.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    if actual!=set(expected)|{'deployment_allowlist.py'}:raise ValueError('unexpected_source_files')
    return expected

def compile_sources(output):
    if os.name!='nt':raise ValueError('windows_x64_build_required')
    windows=Path(os.environ.get('WINDIR',r'C:\Windows'))
    csc=windows/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    gac=windows/'Microsoft.NET/assembly/GAC_MSIL'
    def assembly(name):
        matches=list((gac/name).glob('v4.0_4.0.0.0__*/'+name+'.dll'))
        if len(matches)!=1:raise ValueError('required_framework_reference_missing')
        return str(matches[0])
    def build(target,names,refs):
        p=subprocess.run([str(csc),'/nologo','/target:exe','/platform:x64','/out:'+str(output/target),*['/r:'+r for r in refs],*[str(output/n) for n in names]],capture_output=True,text=True,encoding='mbcs',errors='replace',timeout=60)
        if p.returncode:raise RuntimeError('compile_failed: '+target+'\n'+p.stdout[:6000])
    build('network-probe.exe',['NetworkProbe.cs'],[])
    build('wfp/ClaudeWfpGuard.exe',['wfp/ClaudeWfpGuard.cs'],['System.Web.Extensions.dll'])
    refs=['System.Web.Extensions.dll',assembly('UIAutomationClient'),assembly('UIAutomationTypes'),assembly('WindowsBase')]
    build('native-launcher/DevToolsUi.exe',['native-launcher/DevToolsUi.cs','native-launcher/MainInspectorUiCandidate.cs','native-launcher/MainInspectorMenuDiagnostic.cs'],refs)

def build(output):
    expected=verify_source();output=fresh_destination(output)
    shutil.copytree(SOURCE,output,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    # Failed build output is left for inspection, never launched or installed.
    (output/'hold.block').write_text('Source snapshot: deployment and acceptance pending. No application use.\n',encoding='ascii')
    compile_sources(output)
    folder=output/'native-launcher'
    (folder/'helper-manifest.json').write_text(json.dumps({'schema_version':1,'helper_executable':'DevToolsUi.exe','sha256':sha(folder/'DevToolsUi.exe')},indent=2),encoding='utf8')
    (folder/'native-rtc-manifest.json').write_text(json.dumps({'schema':1,'runtime_sha256':sha(folder/'native_rtc_runtime.js'),'module_sha256':sha(folder/'native_rtc_policy.py')},indent=2),encoding='utf8')
    result={'schema':1,'built':True,'installed':False,'live_acceptance':False,'source_files_verified':len(expected),
        'artifacts':{n:sha(output/n) for n in ('network-probe.exe','wfp/ClaudeWfpGuard.exe','native-launcher/DevToolsUi.exe')},
        'limits':['Source-only build, not an installed or accepted network guard.','No third-party runtime or application binaries redistributed.']}
    (output/'build-result.json').write_text(json.dumps(result,indent=2),encoding='utf8')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    try:print(json.dumps(build(a.output)));return 0
    except Exception as e:print(json.dumps({'built':False,'installed':False,'error':str(e)[:6500]}));return 2
if __name__=='__main__':sys.exit(main())
