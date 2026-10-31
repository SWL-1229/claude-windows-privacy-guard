"""Apply per-user fail-closed site proxy policy to installed Chromium browsers.

Inline PAC is mandatory and self-contained. No web history/profile data is read.
"""
from pathlib import Path
import base64
import datetime
import json
import sys
import winreg

ROOT = Path(__file__).resolve().parent
POLICIES = {
    'Chrome': r'Software\Policies\Google\Chrome',
    'Edge': r'Software\Policies\Microsoft\Edge',
    'Lenovo': r'Software\Policies\Lenovo\SLBrowser',
}


def make_pac(domains):
    return '''function FindProxyForURL(url, host) {
  host = String(host).toLowerCase().replace(/\\.+$/, "");
  var roots = %s;
  for (var i=0; i<roots.length; i++) {
    var root = roots[i];
    if (host === root || host.slice(-(root.length+1)) === "."+root) {
      return "PROXY 127.0.0.1:17894";
    }
  }
  return "PROXY 127.0.0.1:17893";
}
''' % json.dumps(domains)


def values(browser, domains, pac):
    url = 'data:application/x-ns-proxy-autoconfig;base64,' + base64.b64encode(pac.encode('ascii')).decode('ascii')
    result = {
        'ProxySettings': (winreg.REG_SZ, json.dumps({'ProxyMode': 'pac_script',
                            'ProxyPacUrl': url, 'ProxyPacMandatory': True})),
        'QuicAllowed': (winreg.REG_DWORD, 0),
    }
    # These match protected origins, not other sites. Runtime policy support is
    # verified in each browser; unsupported policies are not reported as applied.
    if browser in POLICIES:
        result['WebRtcIPHandlingUrl'] = (winreg.REG_SZ, json.dumps([
            {'url': 'https://[*.]'+d, 'handling': 'disable_non_proxied_udp'}
            for d in domains]))
    return result


def apply():
    domains = json.loads((ROOT/'browser-domains.json').read_text(encoding='utf-8'))
    pac = make_pac(domains)
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    backup = {'created': stamp, 'browsers': {}}
    for browser, key in POLICIES.items():
        state = {}
        requested = values(browser, domains, pac)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_READ|winreg.KEY_SET_VALUE) as k:
            for name, (kind, value) in requested.items():
                try:
                    prior, prior_kind = winreg.QueryValueEx(k, name)
                    state[name] = {'exists': True, 'kind': prior_kind, 'value': prior}
                except FileNotFoundError:
                    state[name] = {'exists': False}
            backup['browsers'][browser] = {'key': key, 'values': state}
    backup_path = ROOT/('browser-policy-backup-'+stamp+'.json')
    backup_path.write_text(json.dumps(backup, indent=2), encoding='utf-8')
    for browser, key in POLICIES.items():
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:
            for name, (kind, value) in values(browser, domains, pac).items():
                winreg.SetValueEx(k, name, 0, kind, value)
    (ROOT/'browser-protection.pac').write_text(pac, encoding='ascii')
    (ROOT/'browser-policy-current.json').write_text(json.dumps({
        'backup': backup_path.name, 'domains': domains,
        'browsers': list(POLICIES), 'protectedProxy': '127.0.0.1:17894',
        'normalProxy': '127.0.0.1:17893', 'pacMandatory': True}, indent=2), encoding='utf-8')
    print(json.dumps({'applied': list(POLICIES), 'backup': backup_path.name, 'domains': len(domains)}))


def restore(backup_name):
    backup = json.loads((ROOT/backup_name).read_text(encoding='utf-8'))
    for obj in backup['browsers'].values():
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, obj['key'], 0, winreg.KEY_SET_VALUE) as k:
            for name, old in obj['values'].items():
                if old['exists']:
                    winreg.SetValueEx(k, name, 0, old['kind'], old['value'])
                else:
                    try:
                        winreg.DeleteValue(k, name)
                    except FileNotFoundError:
                        pass
    print('Only the backed-up browser policy values were restored.')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--restore':
        restore(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == '--apply':
        apply()
    else:
        raise SystemExit('Use --apply or --restore <backup-file-name>')
