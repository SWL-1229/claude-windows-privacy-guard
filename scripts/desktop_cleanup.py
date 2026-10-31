"""Inventory/reset Claude Desktop local authentication stores on Windows.

Default is read-only. --apply requires an explicitly discovered Claude data root.
No credentials are exported/backed up; MCP config, worktrees, Local State and
application preferences are preserved. Web-site drafts/offline state are reset.
"""
from __future__ import annotations
import argparse,datetime,hashlib,json,os,shutil,sqlite3,subprocess,tempfile
from pathlib import Path

STORES=('Network','Local Storage','Session Storage','IndexedDB','WebStorage',
        'Service Worker','Storage','File System','Shared Dictionary','blob_storage',
        'Cache','Code Cache','GPUCache','GPUPersistentCache','DawnGraphiteCache',
        'DawnWebGPUCache','GrShaderCache','ShaderCache','Crashpad','logs','sentry','Sessions')
FILES=('ant-did','fcache','Cookies','Cookies-journal','Cookies-wal','Cookies-shm',
       'ant-device-registry.json','plan-usage-history.json',
       'Login Data','Login Data-journal','Login Data-wal','Login Data-shm',
       'Network Persistent State','TransportSecurity','SharedStorage',
       'SharedStorage-wal','SharedStorage-shm','DIPS','DIPS-journal','DIPS-wal','DIPS-shm',
       'declarative_performance_observer.db','declarative_performance_observer.db-journal',
       'declarative_performance_observer.db-wal','declarative_performance_observer.db-shm')
PRESERVE=('claude_desktop_config.json','git-worktrees.json','Local State','Preferences')
CONFIG_LOGIN_KEYS=('windowSizeWasSignedIn','planUsageLastTrayOpenAt',
                   'lastKnownAccountUuid','oauth:tokenCache','oauth:tokenCacheV2')

def powershell(script):
    p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
                     capture_output=True,text=True,encoding='utf-8',errors='replace',check=True)
    return json.loads(p.stdout.lstrip('\ufeff').strip() or '[]')

def discover_roots(packages,local,roaming):
    """Known layouts only; package presence gates the modern MSIX layout."""
    if not isinstance(packages,list) or any(not isinstance(p,dict) for p in packages):
        raise RuntimeError('Unsupported package discovery result')
    local=Path(local);roaming=Path(roaming)
    candidates=[roaming/'Claude',local/'Claude']
    for pkg in packages:
        family=pkg.get('PackageFamilyName','')
        if family=='Claude_pzs8sxrjxfjjc':
            # Current MSIX releases use this physical Electron userData root.
            # Only the installed, exact known family is eligible; no globbing.
            candidates.append(local/'Claude-Data'/family.lower())
            candidates.append(local/'Packages'/family/'LocalCache'/'Roaming'/'Claude')
            candidates.append(local/'Packages'/family/'LocalCache'/'Local'/'Claude')
    roots=[]
    for path in candidates:
        if path.is_dir():
            real=path.resolve(strict=True)
            if real!=path.absolute():raise RuntimeError('Claude root contains a reparse/redirected path; review the physical location before cleanup')
            # Existing Codex MSIX-redirection must not select Codex's own cache.
            if any(part.lower().startswith('openai.codex_') for part in real.parts):
                raise RuntimeError('Claude path redirected into Codex package; locate real app root explicitly')
            if real not in roots:roots.append(real)
    return roots

def discover():
    packages=powershell("[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); @(Get-AppxPackage -Name Claude | Select-Object Name,PackageFamilyName,PackageFullName,InstallLocation) | ConvertTo-Json -Compress")
    if isinstance(packages,dict):packages=[packages]
    return packages,discover_roots(packages,os.environ['LOCALAPPDATA'],os.environ['APPDATA'])

def assert_closed():
    found=powershell("[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); @(Get-CimInstance Win32_Process -Filter \"Name='Claude.exe'\" | Select-Object ProcessId) | ConvertTo-Json -Compress")
    if found:raise RuntimeError('Claude process is running; save work and fully exit the desktop app before cleanup')

def validate_tree(path,root):
    if not path.exists() and not path.is_symlink():return
    if path.parent!=root or path.resolve(strict=True)!=path.absolute():
        raise RuntimeError('Cleanup target is not an immediate, non-redirected Claude child')
    for p in [path,*path.rglob('*')] if path.is_dir() else [path]:
        if p.is_symlink() or p.resolve(strict=True)!=p.absolute() or not p.resolve().is_relative_to(root):
            raise RuntimeError('Reparse/symlink entry refused; no recursive deletion performed')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None

def cookie_count(root):
    counts=[]
    for rel in ('Network/Cookies','Cookies'):
        p=root/rel
        if not p.is_file():continue
        # SQLite mode=ro may still create a WAL shared-memory file. Count on a
        # disposable complete DB+sidecar copy, then destroy it before deletion.
        with tempfile.TemporaryDirectory(prefix='claude-cookie-audit-') as temp:
            copy=Path(temp)/'Cookies';shutil.copy2(p,copy)
            for suffix in ('-wal','-shm','-journal'):
                side=Path(str(p)+suffix)
                if side.is_file():shutil.copy2(side,Path(str(copy)+suffix))
            c=sqlite3.connect(copy.as_uri()+'?mode=ro',uri=True,timeout=1)
            try:
                if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cookies'").fetchone():
                    raise RuntimeError('Unrecognized Cookies database; refusing this root cleanup')
                if c.execute('PRAGMA quick_check').fetchone()[0]!='ok':
                    raise RuntimeError('Cookies integrity check failed; refusing this root cleanup')
                counts.append(c.execute('SELECT count(*) FROM cookies').fetchone()[0])
            finally:c.close()
    return sum(counts)

def clean_owned_root(root,allowed_roots,apply=False):
    raw=Path(root)
    if not raw.is_absolute() or raw.resolve(strict=True)!=raw.absolute():
        raise RuntimeError('An exact absolute, non-redirected Claude root is required')
    root=raw.resolve(strict=True)
    if root not in [Path(r).resolve(strict=True) for r in allowed_roots]:
        raise RuntimeError('Root is not one of the discovered Claude Desktop data roots')
    targets=[root/n for n in (*STORES,*FILES) if (root/n).exists() or (root/n).is_symlink()]
    for p in targets:validate_tree(p,root)
    # Config is selectively rewritten, so validate it as strictly as deletion
    # targets. A symlink/junction must never redirect a write outside this root.
    for name in (*PRESERVE,'config.json'):
        validate_tree(root/name,root)
    preserved={n:digest(root/n) for n in PRESERVE}
    config=root/'config.json';data=None;keys=[]
    if config.is_file():
        data=json.loads(config.read_text(encoding='utf-8-sig'))
        if not isinstance(data,dict):raise RuntimeError('Unsupported application configuration format')
        keys=[k for k in CONFIG_LOGIN_KEYS if k in data]
    report={'root':str(root),'applied':apply,'cookies_before':cookie_count(root),
            'selected_entries':[p.name for p in targets],
            'selected_files':sum(sum(1 for f in p.rglob('*') if f.is_file()) if p.is_dir() else 1 for p in targets),
            'login_ui_keys_selected':keys,'preserved_config_files':[n for n,h in preserved.items() if h]}
    if apply:
        for p in targets:
            validate_tree(p,root)
            if p.is_dir():shutil.rmtree(p)
            else:p.unlink()
        if keys:
            for k in keys:data.pop(k,None)
            fd,temp=tempfile.mkstemp(prefix='.claude-login-reset-',dir=root)
            try:
                with os.fdopen(fd,'w',encoding='utf-8') as s:
                    json.dump(data,s,ensure_ascii=False,indent=2);s.flush();os.fsync(s.fileno())
                os.replace(temp,config)
            finally:
                if os.path.exists(temp):os.unlink(temp)
        report['preserved_files_verified']=all(digest(root/n)==h for n,h in preserved.items())
        if not report['preserved_files_verified']:raise RuntimeError('Preserved configuration changed during cleanup')
        report['remaining_selected_entries']=[n for n in (*STORES,*FILES) if (root/n).exists()]
        report['cookies_after']=cookie_count(root)
        report['login_ui_keys_remaining']=[]
        if config.is_file():
            after=json.loads(config.read_text(encoding='utf-8-sig'))
            report['login_ui_keys_remaining']=[k for k in CONFIG_LOGIN_KEYS if k in after]
            expected={k:v for k,v in data.items() if k not in CONFIG_LOGIN_KEYS}
            if after!=expected:raise RuntimeError('Normal application configuration changed during cleanup')
        report['normal_config_verified']=True
        if report['remaining_selected_entries'] or report['cookies_after'] or report['login_ui_keys_remaining']:
            raise RuntimeError('Selected login stores were recreated or incompletely removed')
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    scope=p.add_mutually_exclusive_group()
    scope.add_argument('--root',help='Exact discovered Claude data directory')
    scope.add_argument('--all-discovered',action='store_true',help='Explicitly select all currently discovered Claude Desktop roots')
    p.add_argument('--apply',action='store_true');p.add_argument('--report',type=Path)
    a=p.parse_args();packages,roots=discover()
    if a.apply and not (a.root or a.all_discovered):raise RuntimeError('--apply requires --root or --all-discovered; inventory first')
    if a.apply and not roots:raise RuntimeError('No known Claude data roots found; nothing was cleaned')
    assert_closed()
    report_file=None
    if a.report:
        report_path=a.report.resolve()
        if any(report_path==r or report_path.is_relative_to(r) for r in roots):
            raise RuntimeError('Report must be outside all Claude data roots')
        if a.report.exists() or a.report.is_symlink():
            raise RuntimeError('Report already exists; choose a new per-run path')
        report_path.parent.mkdir(parents=True,exist_ok=True)
        report_file=report_path.open('x',encoding='utf-8')
    chosen=[Path(a.root)] if a.root else roots
    completed=[]
    try:
        # Reject an unsupported later root before deleting any earlier root.
        # This is prevalidation, not an all-filesystem atomic transaction.
        if a.apply:
            for root in chosen:clean_owned_root(root,roots,False)
        for root in chosen:completed.append(clean_owned_root(root,roots,a.apply))
        result={'at':datetime.datetime.now().astimezone().isoformat(),'packages':packages,
                'discovered_roots':[str(r) for r in roots],'applied':a.apply,'profiles':completed,
                'limits':['Local authentication/cache reset only; cloud conversations and server sessions are not deleted.',
                          'Local web drafts/offline state are removed; MCP configuration, worktrees and user files are preserved.',
                          'Hardware-derived fingerprints are not reset.']}
        if report_file:json.dump(result,report_file,ensure_ascii=False,indent=2)
    except Exception as error:
        if report_file:json.dump({'outcome':'failed_possibly_partial' if a.apply else 'inventory_failed',
                                 'profiles_completed':completed,'error_type':type(error).__name__},report_file)
        raise
    finally:
        if report_file:report_file.close()
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
