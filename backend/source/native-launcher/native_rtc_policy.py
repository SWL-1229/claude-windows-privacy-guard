"""Owned official Node-inspector bootstrap and native Electron policy proof.

No command-line inspect switches, signed bundle changes, page API replacement,
authentication reads, network fallback, or persistent debugging endpoint.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import time
from urllib.parse import urlsplit

LOADED_MODULE_SHA256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
POLICY = 'disable_non_proxied_udp'
FIELDS = {'schema','kind','pid','creation','nonce','sourceSha256','ok','policy',
          'webContents','listenerAttached','failures','writes','writeFailures','epoch'}

def pins(root, leases):
    folder=Path(root)/'native-launcher'
    manifest=leases.read_json(folder/'native-rtc-manifest.json',root)
    if (set(manifest)!={'schema','runtime_sha256','module_sha256'} or
            type(manifest['schema']) is not int or manifest['schema']!=1):
        raise leases.LeaseError('native_rtc_manifest_invalid')
    for key,name in (('runtime_sha256','native_rtc_runtime.js'),('module_sha256','native_rtc_policy.py')):
        value=manifest[key]
        path=leases.physical(folder/name,root)
        if (type(value) is not str or not re.fullmatch('[0-9a-f]{64}',value) or
                path.stat().st_size>131072 or hashlib.sha256(path.read_bytes()).hexdigest()!=value or
                (key=='module_sha256' and value!=LOADED_MODULE_SHA256)):
            raise leases.LeaseError('native_rtc_source_changed')
    return manifest

def validate_value(value,target,nonce,source,now):
    if (type(value) is not dict or set(value)!=FIELDS or
            type(value['schema']) is not int or value['schema']!=1 or
            value['kind']!='native-electron-rtc-policy-v1' or value['ok'] is not True or
            type(value['pid']) is not int or value['pid']!=target['pid'] or
            value['creation']!=target['creation'] or value['nonce']!=nonce or
            not re.fullmatch('[0-9a-f]{32}',nonce) or value['sourceSha256']!=source or
            value['policy']!=POLICY or value['listenerAttached'] is not True or type(value['failures']) is not int or value['failures']!=0 or
            any(type(value[k]) is not int or value[k]<0 for k in ('writes','writeFailures')) or
            type(value['epoch']) not in (int,float) or not 0<=now-value['epoch']/1000<=4):
        raise ValueError('native_rtc_proof_invalid')
    rows=value['webContents']
    if (type(rows) is not list or not 1<=len(rows)<=256 or
            any(type(v) is not dict or set(v)!={'id','policy'} or type(v['id']) is not int or
                not 0<v['id']<2**31 or v['policy']!=POLICY for v in rows) or
            len({v['id'] for v in rows})!=len(rows)):
        raise ValueError('native_rtc_contents_invalid')
    return value['epoch']/1000

def verify(root,target,nonce,leases,now=None):
    manifest=pins(root,leases)
    if not leases.same_identity(target,leases.identity(target['pid'])):
        raise leases.LeaseError('native_rtc_identity_changed')
    value=leases.read_json(Path(root)/'native-launcher/native-rtc-runtime.json',root)
    try:return validate_value(value,target,nonce,manifest['runtime_sha256'],time.time() if now is None else now)
    except Exception:raise leases.LeaseError('native_rtc_proof_not_verified') from None

class LocalInspector:
    """Bounded RFC6455 client for one exact local, OS-owner-verified endpoint."""
    def __init__(self,path,timeout=4):
        self.timeout=float(timeout)
        if not 0<self.timeout<=4:raise ValueError('inspector_budget_invalid')
        self.deadline=time.monotonic()+self.timeout
        self.socket=socket.create_connection(('127.0.0.1',9229),self.timeout)
        try:self._handshake(path)
        except BaseException:
            self.socket.close();raise
    def _handshake(self,path):
        key=base64.b64encode(secrets.token_bytes(16)).decode('ascii')
        request=(f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1:9229\r\nUpgrade: websocket\r\n'
                 f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n')
        self.budget();self.socket.sendall(request.encode('ascii'));data=b''
        while not data.endswith(b'\r\n\r\n'):
            data+=self.exact(1)
            if len(data)>8192:raise ValueError('inspector_handshake_large')
        lines=data.decode('ascii').split('\r\n')
        headers=dict((a.strip().lower(),b.strip()) for a,b in
                     (line.split(':',1) for line in lines[1:] if ':' in line))
        expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        if not lines[0].startswith('HTTP/1.1 101 ') or headers.get('sec-websocket-accept')!=expected:
            raise ValueError('inspector_handshake_invalid')
        self.sequence=0
    def budget(self):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('inspector_deadline')
        self.socket.settimeout(remaining)
    def exact(self,n):
        result=b''
        while len(result)<n:
            self.budget()
            value=self.socket.recv(n-len(result))
            if not value:raise ValueError('inspector_eof')
            result+=value
        return result
    def send(self,value,opcode=1):
        data=json.dumps(value,separators=(',',':')).encode() if opcode==1 else value
        mask=secrets.token_bytes(4);n=len(data)
        prefix=bytes([0x80|opcode,0x80|n]) if n<126 else bytes([0x80|opcode,0xfe])+struct.pack('!H',n) if n<65536 else bytes([0x80|opcode,0xff])+struct.pack('!Q',n)
        self.budget();self.socket.sendall(prefix+mask+bytes(v^mask[i%4] for i,v in enumerate(data)))
    def receive(self):
        a,b=self.exact(2);n=b&127
        if b&128 or a&0x70:raise ValueError('inspector_frame_invalid')
        if n==126:n=struct.unpack('!H',self.exact(2))[0]
        elif n==127:n=struct.unpack('!Q',self.exact(8))[0]
        if n>131072:raise ValueError('inspector_frame_large')
        value=self.exact(n);opcode=a&15
        if opcode==9:self.send(value,10);return None
        if opcode!=1 or not a&128:raise ValueError('inspector_non_text_response')
        return json.loads(value)
    def evaluate(self,expression):
        self.deadline=time.monotonic()+self.timeout
        self.sequence+=1
        self.send({'id':self.sequence,'method':'Runtime.evaluate','params':{
            'expression':expression,'returnByValue':True,'awaitPromise':True}})
        for _ in range(32):
            value=self.receive()
            if value is None or value.get('id')!=self.sequence:continue
            if ('error' in value or value.get('result',{}).get('exceptionDetails') or
                    'value' not in value.get('result',{}).get('result',{})):
                raise ValueError('native_rtc_evaluation_failed')
            return value['result']['result']['value']
        raise ValueError('native_rtc_response_missing')
    def close(self):
        self.socket.close()

def inspector_inventory():
    """One fixed owned-inspector HTTP request with a four-second total budget.

    Node's inventory has a Content-Length. Unknown or ambiguous framing is
    rejected instead of allowing HTTPResponse's per-read timeout to extend the
    lifetime of the temporary debugger endpoint.
    """
    deadline=time.monotonic()+4
    connection=socket.create_connection(('127.0.0.1',9229),4)
    def budget():
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('inspector_inventory_deadline')
        connection.settimeout(remaining)
    def exact(length):
        data=b''
        while len(data)<length:
            budget();part=connection.recv(length-len(data))
            if not part:raise ValueError('inspector_inventory_eof')
            data+=part
        return data
    try:
        budget();connection.sendall(b'GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:9229\r\nConnection: close\r\n\r\n')
        header=b''
        while not header.endswith(b'\r\n\r\n'):
            header+=exact(1)
            if len(header)>8192:raise ValueError('inspector_inventory_header_large')
        lines=header[:-4].decode('ascii','strict').split('\r\n')
        if not re.fullmatch(r'HTTP/1\.[01] 200(?: [^\r\n]*)?',lines[0]):
            raise ValueError('inspector_inventory_status')
        headers={}
        for line in lines[1:]:
            name,sep,value=line.partition(':')
            if (not sep or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+",name) or
                    name.lower() in headers or any(ord(c)<32 and c!='\t' for c in value)):
                raise ValueError('inspector_inventory_header_invalid')
            headers[name.lower()]=value.strip()
        length=headers.get('content-length','')
        if ('transfer-encoding' in headers or not re.fullmatch('[0-9]{1,5}',length) or
                not 1<=int(length)<=65536):
            raise ValueError('inspector_inventory_framing_invalid')
        return json.loads(exact(int(length)))
    finally:connection.close()


def _install(root,target,nonce,leases,owner_check):
    """Caller owns the startup network hold and enabled the official UI menu."""
    manifest=pins(root,leases)
    if type(nonce) is not str or not re.fullmatch('[0-9a-f]{32}',nonce):raise ValueError('bad_nonce')
    owner_check(target)
    rows=inspector_inventory()
    if type(rows) is not list or len(rows)!=1 or rows[0].get('type')!='node':raise ValueError('inspector_target_invalid')
    u=urlsplit(rows[0].get('webSocketDebuggerUrl',''))
    if (u.scheme!='ws' or u.hostname!='127.0.0.1' or u.port!=9229 or u.username or
            u.password or u.query or u.fragment or not re.fullmatch('/[0-9a-f-]{36}',u.path)):
        raise ValueError('inspector_url_invalid')
    owner_check(target)
    client=LocalInspector(u.path)
    try:
        meta=client.evaluate('({pid:process.pid,electron:process.versions.electron})')
        if meta!={'pid':target['pid'],'electron':'44.9.3'}:raise ValueError('inspector_process_invalid')
        owner_check(target)
        script_bytes=(Path(root)/'native-launcher/native_rtc_runtime.js').read_bytes()
        if hashlib.sha256(script_bytes).hexdigest()!=manifest['runtime_sha256']:
            raise ValueError('native_rtc_source_changed')
        script=script_bytes.decode('utf-8','strict')
        config={'pid':target['pid'],'creation':target['creation'],'nonce':nonce,
                'sourceSha256':manifest['runtime_sha256'],
                'output':str(Path(root)/'native-launcher/native-rtc-runtime.json')}
        value=client.evaluate(script+'('+json.dumps(config,separators=(',',':'))+')')
        validate_value(value,target,nonce,manifest['runtime_sha256'],time.time())
        return value
    finally:
        # Only our just-verified owned main process receives this fixed close.
        try:
            owner_check(target)
            client.evaluate('(()=>{if(process.pid!=='+str(target['pid'])+
                ')throw Error("identity");setTimeout(()=>process.mainModule.require("node:inspector").close(),100);return true;})()')
        finally:client.close()


def install(root,target,nonce,leases,owner_check,close_inspector):
    """The caller supplies a pinned, owned-official-menu cleanup fallback.

    Cleanup runs even if inventory, hashes or WebSocket handshaking fail. It
    must first wait for normal close, then act only on this same owned endpoint;
    unrelated processes, ports and user-owned inspector sessions are preserved.
    """
    if not callable(close_inspector):raise ValueError('native_rtc_cleanup_required')
    try:return _install(root,target,nonce,leases,owner_check)
    finally:close_inspector()
