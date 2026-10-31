"""Configure a NEW built output, keeping its deployment hold in place.

Reads the operator's private JSON/YAML locally. No values, credentials or actual
IP addresses are printed. No service, firewall, browser, timezone or app starts.
This prepares files only; it does not install protection or issue a ready marker.
"""
from __future__ import annotations
import argparse,hashlib,ipaddress,json,os,secrets,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
HOLD='Source snapshot: deployment and acceptance pending. No application use.\n'

def public_ipv4(value):
    if type(value) is not str:raise ValueError('public_ipv4_required')
    ip=ipaddress.ip_address(value)
    if ip.version!=4 or not ip.is_global or str(ip)!=value:raise ValueError('public_ipv4_required')
    return value

def settings(value):
    keys={'allowed_exit_ips','residential_server','core_executable','package_parent',
          'python_executable','node_executable','browser_executable'}
    if type(value) is not dict or set(value)!=keys:raise ValueError('settings_schema_invalid')
    ips=value['allowed_exit_ips']
    if type(ips) is not list or not 1<=len(ips)<=16 or len(set(ips))!=len(ips):raise ValueError('allowlist_required')
    for ip in ips:public_ipv4(ip)
    public_ipv4(value['residential_server'])
    return value

def physical(value,directory=False):
    if type(value) is not str or any(c in value for c in '\0\r\n'):raise ValueError('invalid_runtime_path')
    raw=Path(value)
    if not raw.is_absolute() or '..' in raw.parts or raw.resolve(strict=True)!=raw.absolute():raise ValueError('runtime_path_not_physical')
    if (directory and not raw.is_dir()) or (not directory and not raw.is_file()):raise ValueError('runtime_path_type_invalid')
    for p in (raw,*raw.parents):
        if p.is_symlink() or getattr(p.stat(),'st_file_attributes',0)&0x400:raise ValueError('runtime_reparse_refused')
    return raw

def topology(config,server):
    if type(config) is not dict:raise ValueError('core_config_invalid')
    supported={'mixed-port','bind-address','allow-lan','ipv6','mode','log-level',
        'external-controller','secret','proxies','rules','tun','dns','interface-name'}
    if set(config)-supported:raise ValueError('unsupported_core_options')
    # Do not carry hidden DNS/TUN listeners or alternative proxy listeners into
    # the supposedly exclusive local topology. Scoped DNS is a separate service.
    for name in ('dns','tun'):
        section=config.get(name,{})
        if type(section) is not dict or section.get('enable',False) is not False or section.get('listen'):
            raise ValueError('extra_core_network_service_refused')
    if (config.get('mode')!='rule' or config.get('mixed-port')!=17895 or config.get('bind-address')!='127.0.0.1'
        or config.get('allow-lan') is not False or config.get('ipv6') is not False
        or config.get('external-controller')!='127.0.0.1:17896'
        or config.get('rules')!=['MATCH,PINNED-RESIDENTIAL']
        or any(config.get(k) for k in ('proxy-groups','listeners','proxy-providers','rule-providers'))
        or config.get('tun',{}).get('enable',False)):
        raise ValueError('dedicated_core_topology_invalid')
    proxies=config.get('proxies')
    if type(proxies) is not list or len(proxies)!=2 or any(type(p) is not dict for p in proxies):raise ValueError('two_concrete_proxies_required')
    entry,final=proxies
    if entry.get('name')!='PINNED-ENTRY' or entry.get('type') not in ('vless','vmess','ss','trojan','hysteria2','tuic','socks5','http') or entry.get('dialer-proxy'):
        raise ValueError('concrete_entry_required')
    if (final.get('name')!='PINNED-RESIDENTIAL' or final.get('type')!='socks5'
        or final.get('server')!=server or final.get('dialer-proxy')!='PINNED-ENTRY'
        or final.get('udp',False) is not False):raise ValueError('socks5_residential_exit_required')
    for proxy in proxies:
        if (type(proxy.get('server')) is not str or not proxy['server'] or type(proxy.get('port')) is not int
            or not 1<=proxy['port']<=65535):raise ValueError('proxy_endpoint_invalid')
    if not all(type(final.get(k)) is str and bool(final[k]) for k in ('username','password')):raise ValueError('residential_credentials_required')
    # A fresh controller secret is generated locally, never copied from author.
    config=dict(config);config['secret']=secrets.token_hex(32)
    return config

def prepare(output,settings_file,core_file):
    import yaml  # PyYAML is needed only for explicit private configuration.
    output=physical(str(output),True)
    if output.name.casefold()=='.claude-network-guard':raise ValueError('live_installation_refused')
    if (output/'installed.json').exists() or (output/'configured.json').exists():raise ValueError('already_configured_or_installed')
    result=json.loads((output/'build-result.json').read_text(encoding='utf8'))
    if result.get('built') is not True or result.get('installed') is not False:raise ValueError('fresh_build_required')
    if (output/'hold.block').read_text(encoding='ascii')!=HOLD:raise ValueError('original_deployment_hold_required')
    if (output/'deployment_allowlist.py').read_bytes()!=(HERE/'source/deployment_allowlist.py').read_bytes():raise ValueError('allowlist_source_already_changed')
    for name,digest in result['artifacts'].items():
        if hashlib.sha256((output/name).read_bytes()).hexdigest()!=digest:raise ValueError('build_artifact_changed')
    value=settings(json.loads(physical(str(settings_file)).read_text(encoding='utf-8-sig')))
    paths={k:str(physical(value[k],k=='package_parent')) for k in value if k.endswith('_executable') or k=='package_parent'}
    if Path(paths['python_executable']).name.lower()!='python.exe' or not Path(paths['python_executable']).with_name('pythonw.exe').is_file():raise ValueError('python_and_pythonw_required')
    config=topology(yaml.safe_load(physical(str(core_file)).read_text(encoding='utf-8-sig')),value['residential_server'])
    files={'policy.json':{'allowed_exit_ips':value['allowed_exit_ips']},
        'runtime.json':{k:paths[k] for k in ('core_executable','package_parent')},
        'environment-runtime.json':{k:paths[k] for k in ('node_executable','browser_executable','python_executable')},
        'environment-enforcement.json':{'schema':1,'enabled':True},
        'browser-domains.json':['claude.ai','claude.com','anthropic.com','claude.app','claudeusercontent.com','claudemcpcontent.com']}
    for name in files:
        if (output/name).exists():raise ValueError('configuration_target_exists')
    core=output/'core'
    if core.exists():raise ValueError('core_directory_exists')
    core.mkdir()
    for name,content in files.items():
        with (output/name).open('x',encoding='utf8') as f:json.dump(content,f,indent=2)
    with (core/'config.yaml').open('x',encoding='utf8') as f:yaml.safe_dump(config,f,sort_keys=False)
    cap='"""Generated LOCAL installation policy. Do not commit. Restart after changes."""\nALLOWED = frozenset('+repr(value['allowed_exit_ips'])+')\nPRIMARY = '+repr(value['residential_server'])+'\n'
    (output/'deployment_allowlist.py').write_text(cap,encoding='utf8')
    report={'schema':1,'configured':True,'installed':False,'live_acceptance':False,
        'network_started':False,'deployment_hold_retained':True,'secrets_printed':False}
    with (output/'configured.json').open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--settings',required=True,type=Path);p.add_argument('--core-config',required=True,type=Path);a=p.parse_args()
    try:print(json.dumps(prepare(a.output,a.settings,a.core_config)));return 0
    except Exception:
        # YAML parser errors can contain complete secret lines. Never echo them.
        print(json.dumps({'configured':False,'installed':False,'error':'configuration_failed_review_inputs_locally','deployment_hold_not_removed':True}));return 2
if __name__=='__main__':sys.exit(main())
