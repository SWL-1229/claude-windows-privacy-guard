"""Live view of the existing guard. No account reads, gate writes or networking.

The guard remains the sole enforcement owner. This observer cannot renew leases,
change routing, restore processes, activate DevTools, or trigger page JavaScript.
"""
from pathlib import Path
import hashlib
import json
import time

import checks

GROUPS = ('network', 'desktop', 'browser')
REASONS={
    'main_final_not_pinned_residential':'Clash 当前最终出口不是已固定的家宽',
    'foreign_hold_preserved':'现有手动锁定仍保留',
    'dedicated_configuration_changed_externally':'专用配置发生外部改动',
    'waiting_stable_selection':'正在等待入口选择稳定',
    'internal_failure':'入口跟随检查暂不可用',
    'main_profile_missing':'Clash 当前配置不存在',
}


def readable_reason(value):
    return REASONS.get(value,'当前诊断：'+value if isinstance(value,str) and len(value)<100 else '暂无有效诊断')


def lease_valid(record, value, leases, now):
    """Bind fresh proof to this exact live process/monitor generation."""
    try:
        born=int(record['target']['creation'],16)/10_000_000-11_644_473_600
        return (record.get('schema') == 1 and value.get('schema') == 1
                and value.get('nonce') == record.get('nonce') and value.get('ok') is True
                and checks.fresh(value.get('checked_at'),now)
                and checks.fresh(value.get('written_at'),now)
                and born <= value['checked_at'] <= value['written_at']
                and leases.alive(record['target']) and leases.alive(record['monitor']))
    except Exception:
        return False


def nrpt_matches(rows):
    roots=('claude.ai','claude.com','anthropic.com','claude.app','claudeusercontent.com','claudemcpcontent.com')
    wanted={prefix+root for root in roots for prefix in ('','.')}
    found=set()
    for row in rows:
        names=row.get('Namespace',[])
        servers=row.get('NameServers',[])
        if isinstance(names,str):names=[names]
        if isinstance(servers,str):servers=servers.replace(';',',').split(',')
        if {str(v).strip() for v in servers} == {'127.0.0.1'}:
            found.update(str(v).lower().strip() for v in names)
    return wanted.issubset(found)


class LiveMonitor:
    def __init__(self, root=checks.ROOT):
        self.root=Path(root)
        self.leases=checks.load_module('live_leases','environment_lease.py',self.root)
        self.watchdog=checks.load_module('live_watchdog','environment_watchdog.py',self.root)
        module=checks.load_module('live_desktop','native-launcher/native_desktop_launch.py',self.root)
        self.backend=module.WindowsBackend(self.root)
        self.records=[]
        self.records_at=0
        self.records_error=False
        self.identities={}
        self.roles={}
        self.inventory_at=0
        self.inventory_error='inventory_pending'
        self.nrpt=None
        self.wfp=None
        self.aux_at=0
        self.events=[]
        self.last_signature=None
        self.unregistered_native=[]
        self.guard_sha=hashlib.sha256((self.root/'guard.py').read_bytes()).hexdigest()

    def inventory(self):
        try:
            roles=self.backend.check_services(self.backend.service_snapshot())
            identities={k:self.leases.identity(v['ProcessId']) for k,v in roles.items() if v}
            self.roles,self.identities=roles,identities
            self.inventory_error=None
            # Distinguish an unprotected ordinary app launch from an app that
            # simply isn't running. Never read account databases or page data.
            mains=[]
            for process in self.backend.guard.claude_process_snapshot():
                argv=self.backend.guard.windows_command_line_args(process.get('CommandLine',''))
                if any(arg.partition('=')[0].lower()=='--type' for arg in argv):continue
                identity=self.leases.identity(process['ProcessId'])
                if identity and Path(identity['image']).name.lower()=='claude.exe':mains.append(identity)
            self.unregistered_native=mains
        except Exception as error:
            self.roles,self.identities={},{}
            self.inventory_error=checks.safe_code(error)
        self.inventory_at=time.time()

    def auxiliary(self):
        try:
            script="$r=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | ForEach-Object { [pscustomobject]@{Namespace=@($_.Namespace);NameServers=@($_.NameServers | ForEach-Object {$_.ToString()})} }); ConvertTo-Json -InputObject $r -Depth 5 -Compress"
            rows=self.backend.powershell(script,timeout=8)
            self.nrpt=nrpt_matches(rows) if isinstance(rows,list) else None
        except Exception:
            self.nrpt=None
        # Only the exact fixed helper's read-only list verb; never install/remove.
        try:
            import subprocess
            exe=self.leases.physical(self.root/'wfp/ClaudeWfpGuard.exe',self.root)
            out=subprocess.run([str(exe),'list'],capture_output=True,text=True,encoding='utf-8-sig',errors='replace',
                               timeout=8,creationflags=0x08000000)
            value=json.loads(out.stdout) if out.returncode==0 else None
            self.wfp=value if isinstance(value,dict) and value.get('probe') is False else None
        except Exception:
            self.wfp=None
        self.aux_at=time.time()

    def owned(self, role):
        try:
            return role in self.identities and self.leases.alive(self.identities[role])
        except Exception:
            return None

    def registrations(self):
        # Viewer-only discovery: never ask the enforcement registry to follow
        # orphan ancestry through numeric PIDs reused by unrelated applications.
        if time.time()-self.records_at>=2:
            found=[]
            files=list((self.root/'environment-leases').glob('*.registration.json'))
            self.records_error=len(files)>512
            for file in files[:512]:
                try:
                    record=self.leases.read_json(file,self.root)
                    if record.get('schema')!=1 or record.get('kind') not in ('native','browser'):continue
                    self.leases.validate_identity(record['target'])
                    self.leases.validate_identity(record['monitor'])
                    expected,lease=self.leases.paths(record['kind'],record['target'],record['nonce'],self.root)
                    if file!=expected or record.get('lease_name')!=lease.name:continue
                    found.append(record)
                except Exception:
                    continue
            self.records=found
            self.records_at=time.time()
        creations=self.leases.process_creations()
        active=[]
        for record in self.records:
            target=record['target']
            try:
                if creations.get(target['pid'])==int(target['creation'],16) and self.leases.alive(target):
                    active.append(record)
            except Exception:
                self.records_error=True
        return active

    def snapshot(self):
        now=time.time()
        rows=[]
        def add(key,group,name,state,value,detail,source='现有保护的实时观测',measured=None,ttl=4):
            rows.append(checks.row(key,group,name,state,value,detail,source,measured=measured,ttl=ttl))
        own_gate=self.owned('gate')
        own_core=self.owned('core')
        dns=self.owned('dns_tcp') and self.owned('dns_udp')
        known=self.inventory_error is None and own_gate is not None and own_core is not None
        dns_known=self.inventory_error is None and dns is not None
        add('services','network','保护服务','pass' if known and own_gate and own_core else 'off' if known else 'unknown',
            '服务身份暂未核实' if not known else '网关与专用核心在线' if own_gate and own_core else '保护服务未运行',
            '核对监听进程、路径、启动参数及父子关系。面板不启动服务、不改路由。',
            'Windows 进程身份核对')
        try:
            status=self.leases.read_json(self.root/'status.json',self.root)
        except Exception:status={}
        gate_fresh=(own_gate and status.get('pid')==self.identities['gate']['pid']
                    and checks.fresh(status.get('updated'),now)
                    and status.get('loaded_source_sha256')==self.guard_sha
                    and checks.epoch(status.get('updated'))>=int(self.identities['gate']['creation'],16)/10_000_000-11_644_473_600)
        try:
            allowed=checks.read_small(self.root/'policy.json',self.root)['allowed_exit_ips']
        except Exception:allowed=[]
        exit_ok=gate_fresh and status.get('allowed') is True and status.get('exit_ip') in allowed
        tx=status.get('application_transmission_state')
        permit=exit_ok and tx=='permitted'
        held=(self.root/'hold.block').exists()
        permit=permit and not held
        mode='unknown' if not known else 'off' if not own_gate else 'pass' if permit else 'fail' if gate_fresh else 'unknown'
        if own_gate and held:mode='fail'
        add('admission','network','当前保护状态',mode,
            '等待服务身份核验' if not known else '保护锁定，禁止联网' if own_gate and held else '正在放行' if permit else '保护已暂停传输' if gate_fresh and tx=='suspended' else '保护已阻断' if gate_fresh else '服务未运行' if not own_gate else '等待实时证据',
            '由原有保护网关决定是否传输；本面板不能放行流量。四秒出口许可、50 毫秒本地检查仍由原程序执行。')
        add('exit','network','当前家宽出口','pass' if exit_ok else 'off' if known and not own_gate else 'unknown',
            status.get('exit_ip') if exit_ok else '未取得当前有效出口',
            '取自保护网关现有双来源出口验证，不增加公网探测、不使用系统普通代理的 IP。',
            '原网关出口验证',measured=checks.stamp(status['updated']) if gate_fresh else None)
        try:
            follow=self.leases.read_json(self.root/'ingress-follow-status.json',self.root)
            valid=(checks.fresh(follow.get('updated_at'),now) and self.leases.alive(follow['identity'])
                   and follow['identity']['pid']==follow['pid']
                   and follow.get('source_sha256')==hashlib.sha256((self.root/'ingress_follow.py').read_bytes()).hexdigest())
            good=valid and follow.get('state')=='current' and follow.get('final_credentials_match') is True
            add('ingress','network','链式代理入口','pass' if good else 'fail' if valid and follow.get('state')=='locked' else 'unknown' if own_gate else 'off',
                f"入口已跟随 · {follow.get('entry_type','')}" if good else readable_reason(follow.get('reason',follow.get('state'))),
                '只展示入口协议与住宅配置匹配状态；不读取或显示代理密码。原始诊断：'+str(follow.get('reason',follow.get('state',''))))
        except Exception:
            add('ingress','network','链式代理入口','unknown','暂无有效状态','等待原有入口跟随器发布。')
        route_good=dns and self.nrpt is True and now-self.aux_at<35
        add('dns','network','DNS 防泄露路由','pass' if route_good and dns_known else 'off' if dns_known and not dns else 'unknown',
            '服务身份暂未核实' if not dns_known else '专用 DNS 在线 · Claude 域名已定向' if route_good else '专用 DNS 未运行' if not dns else 'DNS 在线，定向规则未核实',
            '展示现有 DNS 服务身份和系统有效 NRPT 定向：Claude 域名 → 127.0.0.1 → 受保护 DoH。属于路由策略状态，不冒充权威 DNS 泄露实测。',
            '实时 DNS 服务 + 系统有效 NRPT',ttl=4)
        active=self.registrations()
        if self.records_error:
            add('registry','network','环境登记','unknown','环境登记读取失败','不使用历史报告代替当前环境。')
        for kind,group,label in [('native','desktop','Claude 桌面'),('browser','browser','专用网页')]:
            entries=[r for r in active if r.get('kind')==kind]
            if not entries:
                ordinary=kind=='native' and any(self.leases.alive(p) for p in self.unregistered_native)
                add(group+'_runtime',group,label,'fail' if ordinary else 'off',
                    '软件已运行，但没有有效安全登记' if ordinary else '尚未运行',
                    f'请从桌面安全入口启动{label}，面板会自动识别。不清理登录、不自动关闭应用。')
                for key,name in [('timezone','时区'),('language','语言'),('rtc','WebRTC'),('ipv6','IPv6 / UDP')]:
                    add(group+'_'+key,group,name,'unknown' if ordinary else 'off',
                        '等待有效安全登记' if ordinary else '等待应用启动',
                        '只展示这一个安全环境的状态；不借用普通浏览器或本面板的环境值。')
                continue
            for i,record in enumerate(entries):
                prefix=group+str(i)
                suffix='' if len(entries)==1 else f' · 实例 {i+1}'
                ok=False
                reason='environment_proof_unavailable'
                observed=None
                try:
                    _,path=self.leases.paths(kind,record['target'],record['nonce'],self.root)
                    value=self.leases.read_json(path,self.root)
                    observed=value.get('checked_at')
                    ok=lease_valid(record,value,self.leases,time.time())
                    reason=value.get('reason','environment_proof_unavailable')
                    if ok:
                        monitor=self.watchdog.active_monitor(kind,record['target'],root=self.root,verification_mode=record.get('verification_mode'))
                        ok=monitor is not None
                    if ok and kind=='native' and value.get('reason')!='verified':ok=False
                except Exception as error:reason=checks.safe_code(error)
                when=checks.stamp(observed) if checks.epoch(observed) is not None else None
                add(prefix+'_runtime',group,label+suffix,'pass' if ok else 'unknown',
                    '当前环境监控正常' if ok else '已运行，等待有效监控',
                    f"绑定 PID {record['target']['pid']} 与创建时间；监控器必须在线，证据必须在四秒内。诊断：{reason}",
                    '原环境监控器的当前有效证明',measured=when)
                for key,name,result in [('timezone','时区','America/New_York（美东）'),('language','语言','en-US（英语）')]:
                    add(prefix+'_'+key,group,name+suffix,'pass' if ok else 'unknown',result if ok else '等待当前环境验证',
                        '桌面页面由原监控器持续核对。专用网页使用原生进程策略及美东系统时区；启动实测与实时策略监控是不同证据。原生外部组件和云端任务不在页面结论内。',
                        '原环境监控证明 · '+('实时页面' if kind=='native' else '当前进程策略'),measured=when)
                rtc_ok=False
                try:
                    if ok and kind=='native':
                        self.watchdog.native_rtc_policy_module(self.root).verify(self.root,record['target'],record['nonce'],self.leases)
                        rtc_ok=True
                    elif ok:
                        src=self.leases.read_json(Path(record['source']),self.root)
                        rtc=src.get('startup_runtime',{}).get('rtc',{})
                        rtc_ok=record.get('verification_mode')==self.leases.NATIVE_BROWSER_MODE
                        if rtc_ok:
                            # active_monitor already validates immutable startup proof,
                            # identity, command line policy and fresh heartbeat.
                            rtc_ok=rtc.get('status') in ('complete','api_unavailable')
                except Exception:rtc_ok=False
                add(prefix+'_rtc',group,'WebRTC'+suffix,'pass' if rtc_ok else 'unknown',
                    '非代理 UDP 已禁用（当前策略）' if rtc_ok else '未取得当前 WebRTC 策略证明',
                    '桌面：核对当前 Electron 全部 WebContents 的原生策略和监听器。网页：核对原生启动策略、启动时枚举与当前进程监控。策略有效不等于本次重新采集 ICE；私网候选与公网泄露是不同问题。',
                    '当前原生策略；不重新运行 STUN',measured=when)
                add(prefix+'_ipv6',group,'IPv6 / UDP'+suffix,'unknown',
                    '桌面内核规则需只读权限核验' if kind=='native' and self.wfp is None else '沿用现有内核拦截' if kind=='native' else '专用 IPv4 TCP 代理 · QUIC 已禁用' if ok else '等待进程策略验证',
                    '显示保护设计及可读的当前规则；没有权限读取 WFP 时不把安装文件标记当成实时内核证据。网页进程策略和桌面包内核阻断分别核验，不声称所有应用均受保护。',
                    'WFP 只读枚举' if kind=='native' else '专用网页原生进程策略',measured=when)
        diagnostic=status.get('transmission_diagnostic',{}) if gate_fresh else {}
        reason='当前存在离线锁定' if held else diagnostic.get('reason') or status.get('reason') if gate_fresh else 'no_current_guard_evidence'
        signature=(mode,tx if gate_fresh else None,reason)
        if signature!=self.last_signature:
            self.events.append(dict(at=checks.stamp(now),state=mode,message=('放行' if permit else '未放行')+' · '+str(reason)))
            self.events=self.events[-20:]
            self.last_signature=signature
        return dict(schema=1,version='1.1.0',mode='live',started_at=checks.stamp(now),finished_at=checks.stamp(),
                    duration_seconds=round(time.time()-now,3),rows=rows,events=list(self.events),
                    scope='现有 Claude 安全环境的实时可视化；不新增保护、不执行泄露探测',sources=checks.SOURCES)

    def stream(self, callback, stop, refresh):
        import threading
        auxiliary=None
        inventory=None
        while not stop.is_set():
            began=time.monotonic()
            try:
                if (time.time()-self.inventory_at>=12 or refresh.is_set()) and (inventory is None or not inventory.is_alive()):
                    inventory=threading.Thread(target=self.inventory,daemon=True)
                    inventory.start()
                    refresh.clear()
                if time.time()-self.aux_at>=25 and (auxiliary is None or not auxiliary.is_alive()):
                    auxiliary=threading.Thread(target=self.auxiliary,daemon=True)
                    auxiliary.start()
                callback(self.snapshot())
            except Exception as error:
                callback(dict(schema=1,version='1.1.0',mode='live',finished_at=checks.stamp(),events=list(self.events),
                              rows=[checks.row('monitor_error','network','面板数据读取','unknown','暂时无法取得当前状态',
                                               checks.safe_code(error)+'；面板不修改保护，稍后自动重试。','只读观察器',ttl=4)]))
            stop.wait(max(.05,1-(time.monotonic()-began)))
