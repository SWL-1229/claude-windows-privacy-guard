"""Create only a desktop shortcut to the panel; never install network protection."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

REQUIRED=('guard.py','environment_lease.py','environment_watchdog.py',
          'native-launcher/native_desktop_launch.py','installed.json')


def existing_directory(value):
    path=Path(value).expanduser().absolute()
    if not path.is_dir() or path.resolve()!=path:
        raise ValueError('directory_missing_or_redirected')
    return path


def prepare(guard_root, desktop, *, python=None, app=None):
    guard_root=existing_directory(guard_root)
    desktop=existing_directory(desktop)
    if any(not (guard_root/name).is_file() or (guard_root/name).resolve()!=guard_root/name for name in REQUIRED):
        raise ValueError('existing_guard_installation_required')
    app=Path(__file__).with_name('app.py') if app is None else Path(app)
    python=Path(sys.executable).with_name('pythonw.exe') if python is None else Path(python)
    for file in (app,python):
        if not file.is_absolute() or not file.is_file() or file.resolve()!=file:
            raise ValueError('panel_or_pythonw_missing')
    link=desktop/'Claude 运行环境面板.lnk'
    # Preserve any user's existing shortcut. An explicit new name is safer than
    # silently replacing another deployment's link.
    if link.exists():
        raise ValueError('shortcut_already_exists')
    return dict(python=python,app=app,root=guard_root,link=link)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guard-root',type=Path,default=Path.home()/'.claude-network-guard')
    parser.add_argument('--desktop',type=Path,help='可选快捷方式目录，默认 Windows 桌面')
    parser.add_argument('--dry-run',action='store_true',help='只验证路径，不创建快捷方式')
    args=parser.parse_args()
    try:
        if os.name!='nt':raise ValueError('windows_required')
        desktop=args.desktop
        if desktop is None:
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
                "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);[Environment]::GetFolderPath('Desktop')"],
                capture_output=True,text=True,encoding='utf-8-sig',timeout=10,creationflags=0x08000000,check=True)
            desktop=Path(result.stdout.strip())
        values=prepare(args.guard_root,desktop)
        if not args.dry_run:
            env=dict(os.environ)
            env.update(CLAUDE_PANEL_PYTHON=str(values['python']),CLAUDE_PANEL_LINK=str(values['link']),
                       CLAUDE_PANEL_ARGS=subprocess.list2cmdline(['-B',str(values['app']),'--root',str(values['root'])]),
                       CLAUDE_PANEL_FOLDER=str(values['app'].parent))
            script="""$ErrorActionPreference='Stop';
if(Test-Path -LiteralPath $env:CLAUDE_PANEL_LINK){throw 'shortcut_already_exists'}
$s=New-Object -ComObject WScript.Shell;
$l=$s.CreateShortcut($env:CLAUDE_PANEL_LINK);
$l.TargetPath=$env:CLAUDE_PANEL_PYTHON;$l.Arguments=$env:CLAUDE_PANEL_ARGS;
$l.WorkingDirectory=$env:CLAUDE_PANEL_FOLDER;$l.WindowStyle=1;
$l.Description='Claude 安全环境只读实时面板，不安装或修改网络保护';
$icon=Join-Path $env:CLAUDE_PANEL_FOLDER 'detector.ico';if(Test-Path -LiteralPath $icon){$l.IconLocation=$icon};
$l.Save();if(!(Test-Path -LiteralPath $env:CLAUDE_PANEL_LINK)){throw 'shortcut_not_created'}
"""
            subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],env=env,
                           capture_output=True,timeout=15,creationflags=0x08000000,check=True)
        print(json.dumps(dict(ok=True,shortcut_created=not args.dry_run,network_protection_installed=False)))
        return 0
    except Exception as error:
        code=str(error) if isinstance(error,ValueError) else type(error).__name__
        print(json.dumps(dict(ok=False,code=code,network_protection_installed=False)))
        return 2


if __name__=='__main__':sys.exit(main())
