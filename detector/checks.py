"""Read-only, scoped diagnostics. No cleanup, configuration writes, or gate grants."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import datetime as dt
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import math
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time

ROOT = Path.home() / '.claude-network-guard'
TTL = 4.0
STATES = {'pass': '通过', 'fail': '异常', 'unknown': '待验证', 'off': '未运行'}
SOURCES = {
    'webrtc': 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/webrtciphandlingurl',
    'status': 'https://status.claude.com/api',
    'cdp': 'https://chromedevtools.github.io/devtools-protocol/',
}


def stamp(value=None):
    return dt.datetime.fromtimestamp(time.time() if value is None else value, dt.timezone.utc).isoformat()


def epoch(value):
    try:
        if isinstance(value, str):
            parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                return None
            value = parsed.timestamp()
        return float(value) if type(value) in (int, float) and math.isfinite(value) else None
    except (ValueError, OverflowError):
        return None


def fresh(value, now=None, ttl=TTL):
    value = epoch(value)
    return value is not None and 0 <= (time.time() if now is None else now) - value <= ttl


def row(key, group, name, state, value, detail, source, *, measured=None, ttl=None):
    assert state in STATES
    return dict(key=key, group=group, name=name, state=state, value=str(value), detail=str(detail),
                source=source, measured_at=stamp() if measured is None else measured, ttl_seconds=ttl)


def effective_state(item, now=None):
    if item['state'] == 'pass' and item.get('ttl_seconds') is not None:
        if not fresh(item['measured_at'], now, item['ttl_seconds']):
            return 'unknown'
    return item['state']


def accepted_rtc(qa):
    pages = qa.get('pages')
    return (qa.get('complete_target_inventory') is True and isinstance(pages, list) and bool(pages)
            and all(p.get('rtcAccepted') is True and p.get('rtcNoRawAddressObserved') is True
                    and p.get('environmentMatches') is True and p.get('mainDocumentLoaded') is True
                    for p in pages))


def document_accepted(qa):
    pages=qa.get('pages')
    return (qa.get('complete_target_inventory') is True and isinstance(pages,list) and bool(pages)
            and all(isinstance(p,dict) and p.get('environmentMatches') is True
                    and p.get('mainDocumentLoaded') is True and p.get('isErrorDocument') is False
                    and p.get('securityOriginMatchesProtected') is True and p.get('protectedHttpsDocument') is True
                    and p.get('unreachableDocument') is False for p in pages))


def safe_code(error):
    code = getattr(error, 'code', None)
    if not isinstance(code, str):
        code = str(error)
    # Paths, request content and exception payloads never enter reports.
    return code if re.fullmatch(r'[a-z][a-z0-9_]{2,85}', code or '') else type(error).__name__


def read_small(path, root=ROOT):
    path, root = Path(path), Path(root)
    if not path.is_absolute() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('report_path_invalid')
    if path.resolve() != path.absolute() or path.stat().st_size > 2_000_000:
        raise ValueError('report_path_invalid')
    value = json.loads(path.read_text('utf-8-sig'))
    if not isinstance(value, dict):
        raise ValueError('report_format_invalid')
    return value


def load_module(name, relative, root=ROOT):
    root = Path(root)
    if root.resolve() != root.absolute():
        raise ValueError('installation_path_redirected')
    source = root / relative
    if source.resolve() != source.absolute() or not source.resolve().is_relative_to(root.resolve()):
        raise ValueError('module_path_invalid')
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def owned_gate_state(value, role, leases, root, now=None):
    """Status text alone, stale files and reused PIDs never count as evidence."""
    now = time.time() if now is None else now
    if not role or value.get('pid') != role.get('ProcessId') or not fresh(value.get('updated'), now):
        return False
    identity = leases.identity(value['pid'])
    if not identity or os.path.normcase(identity['image']) != os.path.normcase(role.get('ExecutablePath', '')):
        return False
    born = int(identity['creation'], 16) / 10_000_000 - 11_644_473_600
    digest = hashlib.sha256((Path(root) / 'guard.py').read_bytes()).hexdigest()
    return born <= value['updated'] and digest == value.get('loaded_source_sha256')


def tls_probe(port, host, path='/', *, body=False, timeout=6.0):
    """Numeric loopback only. Remote DNS and TLS traverse the explicit gateway.

    No environment proxies, local destination DNS, redirect, cookies, or auth.
    A total deadline shuts down the connection even during a slow response.
    """
    import threading
    if port != 17894 or host not in {'claude.ai', 'anthropic.com', 'www.cloudflare.com',
                                    'api.ipify.org', 'ipwho.is', 'status.claude.com'}:
        raise ValueError('diagnostic_destination_invalid')
    started = time.monotonic()
    channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    channel.settimeout(timeout)
    duplicate = channel.dup()
    def cancel():
        try:
            duplicate.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    timer = threading.Timer(timeout, cancel)
    timer.daemon = True
    timer.start()
    conn = http.client.HTTPSConnection('127.0.0.1', port, timeout=timeout, context=ssl.create_default_context())
    try:
        # HTTPConnection rejects set_tunnel once a socket is assigned.
        conn.set_tunnel(host, 443)
        channel.connect(('127.0.0.1', port))
        conn.sock = channel
        conn._tunnel()
        conn.sock = ssl.create_default_context().wrap_socket(channel, server_hostname=host)
        conn.request('GET' if body else 'HEAD', path, headers={
            'User-Agent': 'Claude-Environment-Detector/1.0', 'Connection': 'close', 'Accept': '*/*'})
        response = conn.getresponse()
        data = response.read(65537) if body else b''
        if len(data) > 65536:
            raise ValueError('response_too_large')
        return dict(status=response.status, ms=round((time.monotonic()-started)*1000),
                    body=data.decode('utf-8', 'replace'))
    finally:
        timer.cancel()
        conn.close()
        channel.close()
        duplicate.close()


def dns_query():
    """Local TCP resolver functionality; deliberately NOT a DNS leak verdict."""
    nonce = secrets.randbelow(65536)
    qname = b'\x06claude\x02ai\x00'
    request = struct.pack('!6H', nonce, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!2H', 1, 1)
    def exact(sock, n):
        data = b''
        while len(data) < n:
            part = sock.recv(n-len(data))
            if not part:
                raise ValueError('dns_response_incomplete')
            data += part
        return data
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
        channel.settimeout(5)
        channel.connect(('127.0.0.1', 53))
        channel.sendall(struct.pack('!H', len(request)) + request)
        size = struct.unpack('!H', exact(channel, 2))[0]
        if not 12 <= size <= 65535:
            raise ValueError('dns_response_invalid')
        reply = exact(channel, size)
    ident, flags, qd, answers, _, _ = struct.unpack('!6H', reply[:12])
    if ident != nonce or not flags & 0x8000 or flags & 15 or qd != 1 or answers < 1:
        raise ValueError('dns_no_valid_answer')
    if reply[12:12+len(qname)+4] != request[12:]:
        raise ValueError('dns_question_mismatch')
    return answers


class Collector:
    def __init__(self, root=ROOT, progress=lambda value: None):
        self.root = Path(root)
        self.progress = progress
        self.rows = []

    def add(self, *args, **kwargs):
        self.rows.append(row(*args, **kwargs))

    def services(self):
        self.progress('核对保护服务的真实进程与监听身份…')
        self.leases = load_module('detector_leases', 'environment_lease.py', self.root)
        self.watchdog = load_module('detector_watchdog', 'environment_watchdog.py', self.root)
        launcher = load_module('detector_desktop', 'native-launcher/native_desktop_launch.py', self.root)
        self.backend = launcher.WindowsBackend(self.root)
        self.roles = self.backend.check_services(self.backend.service_snapshot())
        for role, name in [('gate','保护网关'), ('core','家宽专用核心'), ('dns_tcp','专用 DNS 服务')]:
            p = self.roles.get(role)
            self.add(role, 'network', name, 'pass' if p else 'off',
                     '进程及监听身份匹配' if p else '服务未运行',
                     '只读核对进程路径、监听地址、父子进程与启动参数；不自动启动服务。',
                     '本机 Windows 进程与端口快照', ttl=15)
        self.guard = read_small(self.root/'status.json', self.root)
        self.guard_current = owned_gate_state(self.guard, self.roles.get('gate'), self.leases, self.root)
        current = self.guard_current
        allowed = self.guard.get('allowed') is True and self.guard.get('application_transmission_state') == 'permitted'
        self.add('admission', 'network', '当前联网许可', 'pass' if current and allowed else 'fail' if current else 'unknown',
                 '正在放行' if current and allowed else '当前已阻断' if current else '无有效实时证据',
                 '实际保护网关状态。过期文件不会算作允许；检测器不能授予或续期许可。',
                 '已绑定进程和源码的网关状态', measured=stamp(self.guard['updated']), ttl=4)
        policy = read_small(self.root/'policy.json', self.root)
        self.allowlist = {str(ipaddress.ip_address(v)) for v in policy.get('allowed_exit_ips', [])}
        follow = read_small(self.root/'ingress-follow-status.json', self.root)
        valid = (fresh(follow.get('updated_at')) and self.leases.alive(follow.get('identity', {}))
                 and follow.get('pid') == follow.get('identity', {}).get('pid')
                 and self.leases.identity(follow['pid'])['image'].lower() == str(self.backend.pythonw).lower()
                 and follow.get('source_sha256') == hashlib.sha256((self.root/'ingress_follow.py').read_bytes()).hexdigest())
        good = valid and follow.get('state') == 'current' and follow.get('final_credentials_match') is True
        self.add('ingress', 'network', '入口跟随器', 'pass' if good else 'fail' if valid else 'unknown',
                 '入口与家宽配置一致' if good else '未取得当前有效证明',
                 '入口可切换；当前报告需新鲜、进程身份匹配、住宅凭据匹配。不读取或展示代理密码。',
                 '入口跟随器实时报告', measured=stamp(follow['updated_at']), ttl=4)

    def runtime(self):
        self.progress('读取 Claude 桌面与专用浏览器的绑定证据…')
        records = []
        files = list((self.root/'environment-leases').glob('*.registration.json'))
        if len(files) > 512:
            raise ValueError('too_many_environment_records')
        for file in files:
            try:
                record = self.leases.read_json(file, self.root)
                if record.get('kind') in ('native', 'browser') and self.leases.alive(record['target']):
                    records.append(record)
            except Exception:
                continue
        for kind, group, title in [('native', 'desktop', 'Claude 桌面'), ('browser', 'browser', '专用网页')]:
            active = [r for r in records if r['kind'] == kind]
            if not active:
                self.add(group+'_runtime', group, title+'实际环境', 'off', '未发现运行中的受保护实例',
                         '从桌面安全入口启动后再点一键检测。旧进程和历史报告不计入本次结果；本工具不自动启动应用。', '进程创建身份与保护登记')
                for key, name in [('timezone','时区'),('language','语言'),('rtc','WebRTC 地址枚举')]:
                    self.add(group+'_'+key, group, name, 'unknown', '应用未运行，无法实测',
                             '不能使用检测器自身的时区、语言或 WebRTC 结果代替 Claude。', '目标应用实际运行环境')
                continue
            for index, record in enumerate(active):
                suffix = '' if len(active) == 1 else f' · 实例 {index+1}'
                prefix = group+str(index)
                try:
                    monitor = self.watchdog.active_monitor(kind, record['target'], root=self.root,
                                                           verification_mode=record.get('verification_mode'))
                    if monitor is None:
                        raise ValueError('active_environment_not_verified')
                    if kind == 'native':
                        checked = self.watchdog.native_check(self.root, record['target'], record['nonce'])
                        self.add(prefix+'runtime', group, title+'实际环境'+suffix, 'pass', '当前渲染页面验证通过',
                                 '通过已校验哈希的只读 DevTools helper 读取当前 Live Expression；不是历史启动日志。',
                                 'Claude 桌面当前页面 + 原生策略证明', measured=stamp(checked), ttl=4)
                        for key, name, value in [('timezone','时区','America/New_York'),('language','语言','en-US')]:
                            self.add(prefix+key, group, name+suffix, 'pass', value,
                                     '当前 Claude 顶层页面的实际值；原生组件、外部 MCP、云端 Cowork 不由此证明。',
                                     '已绑定桌面进程的实时页面值', measured=stamp(checked), ttl=4)
                        self.add(prefix+'rtc', group, 'WebRTC 策略'+suffix, 'pass', 'disable_non_proxied_udp',
                                 '已核对目标进程的实时原生策略。策略通过不等同于本次 ICE 候选枚举实测。',
                                 '原生 WebRTC 策略验证器', measured=stamp(checked), ttl=4)
                        self.add(prefix+'rawrtc', group, 'WebRTC 地址枚举'+suffix, 'unknown', '本次未重新采集 ICE 候选',
                                 '未启动 STUN 或摄像头/麦克风。不能凭策略把“无私网/公网候选”判为通过。', '目标桌面候选枚举实测待补充')
                    else:
                        browser = load_module('detector_browser', 'claude_browser_launch.py', self.root)
                        existing = browser.existing_environment(self.root)
                        if not existing or not self.leases.same_identity(existing['target'], record['target']):
                            raise ValueError('browser_identity_not_verified')
                        health = browser.current_document_health(existing, self.root)
                        current, _ = browser._owned_health_status(existing, self.root, browser._publisher_validator())
                        qa = current.get('qa_diagnostic', {})
                        checked = qa.get('checked_at')
                        if not fresh(checked) or checked != health.get('checked_at'):
                            raise ValueError('browser_qa_expired')
                        if (not self.leases.alive(existing['target']) or not self.leases.alive(existing['controller'])
                                or not document_accepted(qa)):
                            raise ValueError('browser_qa_identity_or_document_changed')
                        self.add(prefix+'runtime', group, title+'实际环境'+suffix, 'pass', '当前 Claude 页面完整加载',
                                 '向已绑定进程的现有控制器请求固定只读 QA；不重载页面、不读取页面正文或登录资料。',
                                 '当前页面 QA（所有已观察的受保护顶层页面）', measured=checked, ttl=4)
                        for key,name,value in [('timezone','时区','America/New_York'),('language','语言','en-US')]:
                            self.add(prefix+key, group, name+suffix, 'pass', value,
                                     '本次 QA 要求每个受保护页面 environmentMatches 为真。', '目标浏览器本次页面 QA', measured=checked, ttl=4)
                        rtc_ok = accepted_rtc(qa)
                        self.add(prefix+'rtc', group, 'WebRTC 地址枚举'+suffix, 'pass' if rtc_ok else 'unknown',
                                 '本次未发现原始 IP 候选' if rtc_ok else '未取得完整枚举结果',
                                 '检查 ICE 事件、SDP 与统计中的原始私网/公网 IPv4/IPv6；仅覆盖当前 QA，非持续 STUN 抓包证明。',
                                 '实际专用浏览器页面 QA', measured=checked, ttl=4)
                except Exception as error:
                    self.add(prefix+'runtime', group, title+'实际环境'+suffix, 'unknown', '尚未取得完整实时验证',
                             safe_code(error)+'。保留应用与登录，不尝试绕过保护。', '目标进程及环境验证器')
        self.add('wfp', 'desktop', 'UDP / IPv6 内核拦截', 'unknown', '本次未重新枚举实时 WFP 过滤器',
                 '已安装标记不等于实时内核规则。独立检测器的联网结果也不能替代 Claude 包身份的阻断测试。',
                 '需要专用包身份探测与内核证据')
        self.add('scope', 'desktop', 'Cowork / MCP / 外部组件', 'unknown', '不包含在页面环境结论中',
                 '云端任务出口、独立 MCP 进程和其他浏览器必须分别验收。', '检测范围')

    def network(self):
        self.progress('通过已验证的专用网关做无账号 HTTPS 与 DNS 测试…')
        if not self.roles.get('gate') or not self.roles.get('core'):
            self.add('exit', 'network', '本次实际出口 IP', 'unknown', '专用服务未就绪，未发起请求',
                     '不回退到系统代理或直连。', '固定专用通道')
            for key,name in [('geo','IP 地区 / ASN'),('http_claude','claude.ai 连通性'),
                             ('http_anthropic','anthropic.com 连通性'),('official','Claude 官方服务状态'),
                             ('dns_function','专用 DNS 功能')]:
                self.add(key,'network',name,'unknown','专用服务未就绪，未发起请求',
                         '先从安全入口启动保护环境，然后重新检测。不使用普通网络代替。','未发起公网请求')
            return
        jobs = {
            'cf': lambda: tls_probe(17894, 'www.cloudflare.com', '/cdn-cgi/trace', body=True),
            'ipify': lambda: tls_probe(17894, 'api.ipify.org', '/?format=json', body=True),
            'claude': lambda: tls_probe(17894, 'claude.ai'),
            'anthropic': lambda: tls_probe(17894, 'anthropic.com'),
            'official': lambda: tls_probe(17894, 'status.claude.com', '/api/v2/status.json', body=True),
        }
        if self.roles.get('dns_tcp'):
            jobs['dns'] = dns_query
        outputs = {}
        with ThreadPoolExecutor(max_workers=6) as pool:
            pending = {pool.submit(work): name for name,work in jobs.items()}
            for task in as_completed(pending):
                name = pending[task]
                try:
                    outputs[name] = task.result()
                except Exception as error:
                    outputs[name] = {'error': safe_code(error)}
        ips=[]
        for name in ('cf', 'ipify'):
            result=outputs.get(name,{})
            try:
                if result.get('status')!=200:
                    raise ValueError()
                raw = dict(line.split('=',1) for line in result['body'].splitlines() if '=' in line).get('ip') if name=='cf' else json.loads(result['body'])['ip']
                ips.append(str(ipaddress.ip_address(raw)))
            except Exception:
                pass
        good = len(ips)==2 and len(set(ips))==1 and ips[0] in self.allowlist
        mismatch = bool(ips) and (len(set(ips))>1 or any(ip not in self.allowlist for ip in ips))
        self.add('exit','network','本次实际出口 IP','pass' if good else 'fail' if mismatch else 'unknown',
                 ips[0] if good else '出口不一致或不在允许名单' if mismatch else '两路出口查询未同时完成',
                 'Cloudflare 与 ipify 均经专用网关查询。仅证明该通道本次出口；不伪称 Anthropic 服务器实收 IP 或 IP 独享。',
                 'Cloudflare trace + ipify HTTPS', ttl=15)
        if good:
            try:
                meta=tls_probe(17894,'ipwho.is','/'+ips[0],body=True)
                data=json.loads(meta['body'])
                if meta['status']!=200 or data.get('success') is not True or data.get('ip')!=ips[0]:
                    raise ValueError('ip_metadata_unavailable')
                info={k:data.get(k) for k in ('country','country_code','region','city')}
                connection=data.get('connection',{})
                value=' / '.join(str(info[k])[:90] for k in ('country','region','city') if info[k])
                self.add('geo','network','IP 地区 / ASN','pass' if info['country_code']=='US' else 'fail',value,
                         f"第三方 IP 数据库；ASN {str(connection.get('asn','未知'))[:50]}，ISP {str(connection.get('isp','未知'))[:100]}。城市可能有误差，不代表网页时区。",
                         'ipwho.is（第三方数据库）',ttl=300)
            except Exception:
                self.add('geo','network','IP 地区 / ASN','unknown','第三方资料暂不可用','没有可核对的数据时不推断归属地或住宅属性。','ipwho.is')
        for key,host in [('claude','claude.ai'),('anthropic','anthropic.com')]:
            result=outputs.get(key,{})
            status=result.get('status')
            state='pass' if status and 200<=status<400 else 'unknown' if status in (401,403,429) else 'fail'
            self.add('http_'+key,'network',host+' 连通性',state,
                     f"HTTP {status} · {result['ms']} ms" if status else '请求未完成',
                     'TLS 校验开启，无账号 HEAD 请求。403/429 只说明服务器返回限制，不能证明账号可用或不可用。'+(' '+result.get('error','')),
                     '检测器经同一专用网关的请求（非 Claude 进程任务）',ttl=30)
        official=outputs.get('official',{})
        try:
            if official.get('status')!=200:
                raise ValueError()
            indicator=json.loads(official['body'])['status']['indicator']
            self.add('official','network','Claude 官方服务状态','pass' if indicator=='none' else 'fail',
                     '官方报告无故障' if indicator=='none' else '官方报告存在事件',
                     '全站状态不代表你的账号、套餐或本机链路正常。',SOURCES['status'],ttl=60)
        except Exception:
            self.add('official','network','Claude 官方服务状态','unknown','状态接口未取得有效结果','未将第三方检测结果当成官方状态。',SOURCES['status'])
        dns=outputs.get('dns')
        self.add('dns_function','network','专用 DNS 功能','pass' if type(dns) is int else 'unknown',
                 '本次 TCP DNS 查询有有效回答' if type(dns) is int else '本次未取得有效回答',
                 '只向本机已核验身份的 127.0.0.1:53 发送 claude.ai 查询；不向公网发送 UDP。',
                 '本机专用 DNS TCP 查询',ttl=30)

    def collect(self):
        started=time.time()
        try:
            self.services()
        except Exception as error:
            self.add('installation','network','保护安装 / 服务身份','unknown','保护服务未能完整核验',
                     safe_code(error)+'。未启动服务、未改变网络配置。','本机只读预检')
        if hasattr(self,'roles') and hasattr(self,'allowlist'):
            self.network()
        if hasattr(self,'leases'):
            try:
                self.runtime()
            except Exception as error:
                self.add('runtime_error','desktop','实际应用检查','unknown','检查未完成',safe_code(error),'只读运行时验证器')
        self.add('dns_leak','network','DNS 泄露实测','unknown','未取得目标进程的权威解析观测',
                 'DNS 查询成功或配置正确均不等于无泄露。需要唯一随机域名的权威 DNS 日志与目标进程归因；本次不编造 DNS 出口 IP。', '实测证据缺失')
        self.add('reputation','network','IP 信誉 / 代理 / Tor / 独享','unknown','未接入信誉数据库，不生成评分',
                 'IP 归属地、允许名单匹配不能证明住宅独享、无滥用历史，亦不能得知 Anthropic 内部风控分。','第三方信誉数据尚未接入')
        self.add('fingerprint','desktop','Canvas / WebGL / 设备指纹','unknown','未采集或更改设备指纹',
                 '不同指纹本身不等于风险；本检测器不伪造指纹，也不读取 Cookies、令牌或聊天内容。','检测范围')
        return dict(schema=1,version='1.0.0',started_at=stamp(started),finished_at=stamp(),
                    duration_seconds=round(time.time()-started,2),rows=self.rows,
                    scope='只读快照；当前应用页面、专用链路和第三方信息分别列示',sources=SOURCES)


def export_report(report, hide_ip=True, now=None):
    value=json.loads(json.dumps(report,ensure_ascii=False))
    for item in value['rows']:
        item['state']=effective_state(item,now)
    if hide_ip:
        def redact(obj):
            if isinstance(obj,str):
                obj=re.sub(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])','[IP 已隐藏]',obj)
                def ipv6(match):
                    try:
                        return '[IP 已隐藏]' if ipaddress.ip_address(match.group()).version==6 else match.group()
                    except ValueError:
                        return match.group()
                return re.sub(r'(?<![\w:])[0-9A-Fa-f]*:[0-9A-Fa-f:.]+(?![\w:])',ipv6,obj)
            if isinstance(obj,list): return [redact(v) for v in obj]
            if isinstance(obj,dict): return {k:redact(v) for k,v in obj.items()}
            return obj
        value=redact(value)
    value['exported_at']=stamp(now)
    value['ip_hidden']=hide_ip
    return value
