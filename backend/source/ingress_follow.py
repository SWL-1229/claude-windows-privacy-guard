"""Follow the explicitly selected Clash transit, never its final/shared route.

Candidate only. Production guard.py is deliberately not imported or modified.
All console/status outputs are coarse; proxy credentials remain local.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time
import stat
from urllib.parse import urlsplit
import yaml

ROOT = Path(__file__).resolve().parent
MAIN = Path.home() / 'AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev'
KIND = 'claude-ingress-follow-v1'
from deployment_allowlist import PRIMARY
ENTRY_TYPES = {'vless', 'vmess', 'ss', 'trojan', 'hysteria2', 'tuic', 'socks5', 'http'}
FINAL_KEYS = ('type', 'server', 'port', 'username', 'password', 'tls', 'skip-cert-verify', 'udp')
MAX_BODY = 16 * 1024 * 1024


class FollowError(Exception):
    """Error code, never an upstream exception containing private data."""


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def atomic_json(path, value):
    temp = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    with temp.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def read_mapping(path):
    physical_path(path)
    result = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(result, dict):
        raise FollowError('invalid_configuration')
    return result


def physical_path(path):
    if not path.is_absolute() or path.resolve() != path:
        raise FollowError('nonphysical_configuration_path')
    for item in (path, *path.parents):
        if item.exists() and (item.is_symlink() or
                getattr(item.stat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise FollowError('reparse_configuration_path')


def verify_main_pipe_owner(connection, mixed_port):
    """Bind the named pipe to the same live PID serving main Clash's port."""
    import ctypes
    from ctypes import wintypes
    import msvcrt
    if isinstance(mixed_port, bool) or not isinstance(mixed_port, int) or not 1 <= mixed_port <= 65535:
        raise FollowError('main_mixed_port_invalid')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    get_pid = kernel.GetNamedPipeServerProcessId
    get_pid.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    get_pid.restype = wintypes.BOOL
    pid = wintypes.ULONG()
    if not get_pid(msvcrt.get_osfhandle(connection.fileno()), ctypes.byref(pid)) or not pid.value:
        raise FollowError('main_pipe_owner_unavailable')
    iphlp = ctypes.WinDLL('iphlpapi', use_last_error=True)
    function = iphlp.GetExtendedTcpTable
    function.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD),
                         wintypes.BOOL, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG]
    function.restype = wintypes.DWORD
    size = wintypes.DWORD()
    if function(None, ctypes.byref(size), False, 2, 3, 0) != 122 or size.value > 16 * 1024 * 1024:
        raise FollowError('main_listener_owner_unavailable')
    buffer = ctypes.create_string_buffer(size.value)
    if function(buffer, ctypes.byref(size), False, 2, 3, 0) != 0:
        raise FollowError('main_listener_owner_unavailable')
    import struct
    data = buffer.raw
    count = struct.unpack_from('<I', data)[0]
    if 4 + count * 24 > len(data):
        raise FollowError('main_listener_table_invalid')
    owners = {values[5] for i in range(count)
              if (values := struct.unpack_from('<6I', data, 4 + i * 24))
              and socket.ntohs(values[2] & 65535) == mixed_port
              and values[1] in (0, int.from_bytes(socket.inet_aton('127.0.0.1'), 'little'))}
    if owners != {pid.value}:
        raise FollowError('main_pipe_listener_owner_mismatch')
    return pid.value


def validate_template(template):
    proxies = template.get('proxies')
    if not isinstance(proxies, list) or len(proxies) != 2:
        raise FollowError('dedicated_topology_changed')
    by = {p.get('name'): p for p in proxies if isinstance(p, dict)}
    final = by.get('PINNED-RESIDENTIAL')
    entry = by.get('PINNED-ENTRY')
    if (not final or not entry or final.get('type') != 'socks5'
            or proxies[0].get('name') != 'PINNED-ENTRY'
            or proxies[1].get('name') != 'PINNED-RESIDENTIAL'):
        raise FollowError('dedicated_topology_changed')
    if str(final.get('server')) != PRIMARY or final.get('dialer-proxy') != 'PINNED-ENTRY':
        raise FollowError('final_endpoint_changed')
    if (template.get('mode') != 'rule'
            or template.get('rules') != ['MATCH,PINNED-RESIDENTIAL']
            or template.get('proxy-groups')
            or template.get('listeners')
            or template.get('proxy-providers')
            or template.get('rule-providers')):
        raise FollowError('dedicated_route_not_exclusive')
    if (template.get('mixed-port') != 17895
            or template.get('bind-address') != '127.0.0.1'
            or template.get('allow-lan') is not False
            or template.get('ipv6') is not False
            or template.get('tun', {}).get('enable', False)):
        raise FollowError('dedicated_listener_changed')
    return final


def select_ingress(template, main, live, mode):
    final = validate_template(template)
    proxies = main.get('proxies', [])
    by = {p.get('name'): p for p in proxies if isinstance(p, dict)}
    if len(by) != len(proxies):
        raise FollowError('duplicate_main_proxy_names')
    graph = live.get('proxies')
    if not isinstance(graph, dict):
        raise FollowError('main_live_graph_unavailable')

    def leaf(name):
        seen = set()
        while isinstance(name, str) and name not in seen:
            seen.add(name)
            node = graph.get(name)
            if not isinstance(node, dict):
                raise FollowError('main_selection_unresolved')
            now = node.get('now')
            if isinstance(now, str):
                if node.get('type') in ('URLTest', 'Fallback', 'LoadBalance'):
                    raise FollowError('automatic_group_not_supported')
                name = now
                continue
            result = by.get(name)
            if not result:
                raise FollowError('main_selection_not_concrete')
            return result
        raise FollowError('main_selection_cycle')

    if mode == 'global':
        root = 'GLOBAL'
    elif mode == 'rule':
        roots = [str(r).split(',')[1] for r in main.get('rules', [])
                 if str(r).split(',')[0] in ('MATCH', 'FINAL') and len(str(r).split(',')) == 2]
        if len(roots) != 1:
            raise FollowError('main_match_route_ambiguous')
        root = roots[0]
    else:
        raise FollowError('main_direct_mode_rejected')
    selected = leaf(root)
    if any(selected.get(k) != final.get(k) for k in FINAL_KEYS):
        raise FollowError('main_final_not_pinned_residential')
    live_final = graph[selected['name']]
    if (str(live_final.get('type')).lower() != 'socks5'
            or not isinstance(live_final.get('dialer-proxy'), str)
            or live_final['dialer-proxy'] != selected.get('dialer-proxy')):
        raise FollowError('live_saved_chain_mismatch')
    entry = leaf(live_final['dialer-proxy'])
    live_entry = graph[entry['name']]
    type_aliases = {'ss': 'shadowsocks', 'http': 'http', 'socks5': 'socks5',
                    'vless': 'vless', 'vmess': 'vmess', 'trojan': 'trojan',
                    'hysteria2': 'hysteria2', 'tuic': 'tuic'}
    if str(live_entry.get('type')).lower() != type_aliases.get(entry.get('type')):
        raise FollowError('live_saved_transit_type_mismatch')
    if (entry.get('type') not in ENTRY_TYPES or entry.get('dialer-proxy')
            or live_entry.get('dialer-proxy')):
        raise FollowError('transit_type_or_nested_chain_rejected')
    if entry.get('type') == 'socks5' and entry.get('server') == final.get('server'):
        raise FollowError('residential_hairpin_rejected')
    if not isinstance(entry.get('server'), str) or not entry['server'].strip():
        raise FollowError('transit_server_missing')
    if isinstance(entry.get('port'), bool) or not isinstance(entry.get('port'), int) or not 1 <= entry['port'] <= 65535:
        raise FollowError('transit_port_invalid')
    if not isinstance(entry.get('skip-cert-verify', False), bool):
        raise FollowError('transit_tls_setting_invalid')
    # Preserve the user's existing provider transport settings exactly. Never set
    # skip-cert-verify=True if the selected node did not already specify it.
    copied = copy.deepcopy(entry)
    copied['name'] = 'PINNED-ENTRY'
    candidate = copy.deepcopy(template)
    candidate['proxies'] = [copied if p['name'] == 'PINNED-ENTRY' else p
                            for p in candidate['proxies']]
    if candidate['proxies'][1] != template['proxies'][1]:
        raise FollowError('final_mutation_rejected')
    return candidate, {'entry_type': entry['type'],
                       'entry_fingerprint': digest(entry),
                       'provider_tls_skip_verify': bool(entry.get('skip-cert-verify', False)),
                       'tls_mode': 'preserve_provider',
                       'final_credentials_match': True}


def read_http_response(stream):
    status_line = stream.readline(8193)
    if len(status_line) > 8192:
        raise FollowError('main_response_header_too_large')
    try:
        status = int(status_line.split()[1])
    except Exception:
        raise FollowError('main_response_invalid') from None
    headers = {}
    total = 0
    while True:
        line = stream.readline(8193)
        total += len(line)
        if total > 65536:
            raise FollowError('main_response_header_too_large')
        if line in (b'\r\n', b'\n'):
            break
        if not line or b':' not in line:
            raise FollowError('main_response_invalid')
        key, value = line.split(b':', 1)
        headers[key.strip().lower()] = value.strip().lower()
    if headers.get(b'transfer-encoding') == b'chunked':
        body = bytearray()
        while True:
            line = stream.readline(128)
            try:
                size = int(line.split(b';')[0], 16)
            except Exception:
                raise FollowError('main_chunk_invalid') from None
            if size == 0:
                break
            if size < 0 or len(body) + size > MAX_BODY:
                raise FollowError('main_response_too_large')
            part = stream.read(size)
            if len(part) != size or stream.read(2) != b'\r\n':
                raise FollowError('main_chunk_short')
            body.extend(part)
        return status, bytes(body)
    size = int(headers.get(b'content-length', b'-1'))
    if not 0 <= size <= MAX_BODY:
        raise FollowError('main_response_size_invalid')
    body = stream.read(size)
    if len(body) != size:
        raise FollowError('main_response_short')
    return status, body


def main_pipe_snapshot(main_dir):
    generated_path = main_dir / 'clash-verge.yaml'
    physical_path(generated_path)
    before = generated_path.read_bytes()
    generated = yaml.safe_load(before)
    config = read_mapping(main_dir / 'config.yaml')
    pipe = generated.get('external-controller-pipe')
    if pipe != r'\\.\pipe\verge-mihomo':
        raise FollowError('main_pipe_identity_changed')
    secret = generated.get('secret', config.get('secret', ''))
    if not isinstance(secret, str) or any(c in secret for c in '\r\n'):
        raise FollowError('main_controller_secret_invalid')
    responses = {}
    owner = None
    for path in ('/configs', '/proxies'):
        # Child process bounds potentially blocking Windows pipe I/O. No secret
        # appears in argv, status, errors, or files written by this module.
        with open(pipe, 'r+b', buffering=0) as connection:
            current_owner = verify_main_pipe_owner(connection, generated.get('mixed-port'))
            if owner is not None and owner != current_owner:
                raise FollowError('main_core_changed_during_snapshot')
            owner = current_owner
            wire = (f'GET {path} HTTP/1.1\r\nHost: localhost\r\n'
                    f'Authorization: Bearer {secret}\r\nConnection: close\r\n\r\n').encode()
            connection.write(wire)
            buffered = io.BufferedReader(connection, buffer_size=65536)
            status, body = read_http_response(buffered)
            if status != 200:
                raise FollowError('main_controller_rejected')
            responses[path] = json.loads(body)
    if generated_path.read_bytes() != before:
        raise FollowError('main_profile_changed_during_read')
    return {'main': generated, 'live': responses['/proxies'],
            'mode': responses['/configs'].get('mode')}


def get_main_snapshot(main_dir, script_path=None):
    interpreter = Path(sys.executable)
    if interpreter.name.lower() == 'pythonw.exe':
        interpreter = interpreter.with_name('python.exe')
    completed = subprocess.run([str(interpreter), str(script_path or Path(__file__)),
                                '--pipe-snapshot', '--main-dir', str(main_dir)],
                               capture_output=True, timeout=5, check=False,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if completed.returncode != 0 or len(completed.stdout) > 2 * MAX_BODY:
        raise FollowError('main_snapshot_unavailable')
    return json.loads(completed.stdout)


class OwnedHold:
    def __init__(self, root):
        physical_path(root)
        self.path = root / 'hold.block'
        self.identity_path = root / 'ingress-follow-owner.json'
        if not self.identity_path.exists():
            try:
                with self.identity_path.open('x', encoding='utf-8') as stream:
                    json.dump({'kind': KIND, 'token': secrets.token_hex(32)}, stream)
            except FileExistsError:
                pass
        identity = json.loads(self.identity_path.read_text(encoding='utf-8'))
        if identity.get('kind') != KIND or not isinstance(identity.get('token'), str):
            raise FollowError('hold_owner_invalid')
        self.content = {'kind': KIND, 'token': identity['token']}

    def owns(self):
        try:
            return json.loads(self.path.read_text(encoding='utf-8')) == self.content
        except Exception:
            return False

    def acquire(self):
        try:
            with self.path.open('x', encoding='utf-8') as stream:
                json.dump(self.content, stream)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            if not self.owns():
                raise FollowError('foreign_hold_preserved') from None

    def release(self):
        if not self.owns():
            raise FollowError('hold_owner_changed')
        self.path.unlink()


def core_request(config, method, path, body=None):
    if config.get('external-controller') != '127.0.0.1:17896':
        raise FollowError('core_controller_not_pinned')
    secret = config.get('secret')
    if not isinstance(secret, str) or len(secret) < 32 or any(x in secret for x in '\r\n'):
        raise FollowError('core_controller_secret_invalid')
    connection = http.client.HTTPConnection('127.0.0.1', 17896, timeout=6)
    try:
        data = None if body is None else json.dumps(body).encode()
        connection.request(method, path, body=data,
                           headers={'Authorization': 'Bearer ' + secret,
                                    'Content-Type': 'application/json'})
        response = connection.getresponse()
        response.read(MAX_BODY)
        if response.status not in (200, 204):
            raise FollowError('core_controller_rejected')
    finally:
        connection.close()


def probe_primary():
    checks = []
    for host, path in [('www.cloudflare.com', '/cdn-cgi/trace'), ('api.ipify.org', '/')]:
        connection = http.client.HTTPSConnection('127.0.0.1', 17895, timeout=8,
                                                context=ssl.create_default_context())
        connection.set_tunnel(host, 443)
        try:
            connection.request('GET', path, headers={'Host': host, 'Connection': 'close'})
            response = connection.getresponse()
            body = response.read(2048).decode('utf-8')
            values = dict(s.split('=', 1) for s in body.splitlines() if '=' in s)
            ip = values.get('ip', body.strip())
            checks.append(response.status == 200 and ip == PRIMARY)
            if 'loc' in values and values['loc'] != 'US':
                raise FollowError('exit_country_mismatch')
        except FollowError:
            raise
        except Exception:
            raise FollowError('primary_exit_probe_failed') from None
        finally:
            connection.close()
    if len(checks) != 2 or not all(checks):
        raise FollowError('primary_exit_mismatch')


class Follower:
    def __init__(self, root=ROOT, main_dir=MAIN, snapshot=get_main_snapshot,
                 request=core_request, probe=probe_primary, sleep=time.sleep):
        self.root, self.main_dir = root, main_dir
        self.snapshot, self.request, self.probe, self.sleep = snapshot, request, probe, sleep
        self.config_path = root / 'core/config.yaml'
        self.template = read_mapping(self.config_path)
        validate_template(self.template)
        self.hold = OwnedHold(root)
        self.last_applied = digest(self.template['proxies'][0] | {'name': 'PINNED-ENTRY'})
        self.pending = None
        self.stable = 0

    def selected(self):
        source = self.snapshot(self.main_dir)
        return select_ingress(self.template, source['main'], source['live'], source['mode'])

    def tick(self):
        try:
            if read_mapping(self.config_path) != self.template:
                raise FollowError('dedicated_configuration_changed_externally')
            candidate, evidence = self.selected()
            fingerprint = digest(candidate['proxies'][0])
            if fingerprint != self.last_applied or self.hold.owns():
                self.hold.acquire()
            if fingerprint == self.pending:
                self.stable += 1
            else:
                self.pending, self.stable = fingerprint, 1
            if self.stable < 2:
                return {'state': 'waiting_stable_selection', **evidence}
            if fingerprint == self.last_applied and not self.hold.owns():
                return {'state': 'current', **evidence}
            self.hold.acquire()
            # Local guard watchdog revokes and aborts active connections within
            # its existing 50ms cadence. Explicitly drain core as well.
            self.sleep(0.15)
            self.request(self.template, 'DELETE', '/connections')
            config_text = yaml.safe_dump(candidate, allow_unicode=True, sort_keys=False)
            self.request(self.template, 'PUT', '/configs?force=true', {'payload': config_text})
            self.request(candidate, 'DELETE', '/connections')
            confirmed, _ = self.selected()
            if digest(confirmed['proxies'][0]) != fingerprint:
                raise FollowError('selection_changed_during_reload')
            self.probe()
            confirmed, _ = self.selected()
            if digest(confirmed['proxies'][0]) != fingerprint:
                raise FollowError('selection_changed_during_probe')
            # Persist only after proof; reloading does not alter guard.py or its
            # allowlist. On any write/reload/probe error leave our hold in place.
            target = self.config_path.with_name('config.ingress-' + secrets.token_hex(12) + '.yaml')
            physical_path(target)
            with target.open('x', encoding='utf-8') as stream:
                stream.write(config_text)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(target, self.config_path)
            self.template = candidate
            self.last_applied = fingerprint
            self.hold.release()
            return {'state': 'applied_waiting_guard_fresh_grant', **evidence}
        except FollowError as error:
            # Invalid/missing source must not keep an old allowed route online.
            try:
                self.hold.acquire()
            except FollowError:
                pass
            return {'state': 'locked', 'reason': str(error)}
        except Exception:
            try:
                self.hold.acquire()
            except FollowError:
                pass
            return {'state': 'locked', 'reason': 'internal_failure'}


def process_identity(pid):
    # Exact creation stamp prevents a reused PID validating stale status.
    import ctypes as C
    from ctypes import wintypes as W
    if type(pid) is not int or pid <= 0:
        return None
    k = C.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    k.OpenProcess.restype = W.HANDLE
    k.GetProcessTimes.argtypes = [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4
    k.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
    k.GetExitCodeProcess.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
    k.CloseHandle.argtypes = [W.HANDLE]
    handle = k.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        code = W.DWORD()
        if not k.GetExitCodeProcess(handle, C.byref(code)) or code.value != 259:
            return None
        stamps = [W.FILETIME() for _ in range(4)]
        image, size = C.create_unicode_buffer(32768), W.DWORD(32768)
        if (not k.GetProcessTimes(handle, *[C.byref(x) for x in stamps])
                or not k.QueryFullProcessImageNameW(handle, 0, image, C.byref(size))):
            return None
        created = (stamps[0].dwHighDateTime << 32) | stamps[0].dwLowDateTime
        return {'pid': pid, 'creation': f'{created:016x}',
                'image': os.path.normcase(os.path.abspath(image.value))}
    finally:
        k.CloseHandle(handle)


def lock_is_held(root):
    import msvcrt
    path = root / 'ingress-follow.lock'
    physical_path(path)
    with path.open('a+b') as lock:
        # Windows mandatory byte locks also block reads. Attempt the lock
        # before inspecting/initializing its byte; never read another owner's
        # locked byte merely to check whether the singleton is running.
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            if error.errno in (13, 36) or getattr(error, 'winerror', None) in (32, 33):
                return True
            raise FollowError('follower_lock_unavailable') from None
        try:
            if os.fstat(lock.fileno()).st_size == 0:
                lock.write(b'0'); lock.flush()
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        return False


def valid_follower_status(value, root, started, expected_sha, expected_images, now,
                          actual_identity, held):
    if not isinstance(value, dict) or not held:
        return False
    updated = value.get('updated_at')
    if (type(updated) not in (int, float) or not started <= updated <= now
            or not 0 <= now - updated < 3):
        return False
    expected_source = str(root / 'ingress_follow.py')
    if value.get('source') != expected_source or value.get('source_sha256') != expected_sha:
        return False
    wanted = value.get('identity')
    if (not isinstance(wanted, dict) or not isinstance(actual_identity, dict)
            or wanted != actual_identity or value.get('pid') != wanted.get('pid')
            or type(wanted.get('pid')) is not int or wanted['pid'] <= 0
            or not isinstance(wanted.get('creation'), str)
            or len(wanted['creation']) != 16
            or any(c not in '0123456789abcdef' for c in wanted['creation'])
            or wanted.get('image') not in expected_images):
        return False
    return True


def ensure_running(root=ROOT, timeout=25):
    """Await a new proof from the exact live singleton, never old status.

    Guard must already be running. No holds or service settings are changed.
    A follower needs one new source snapshot AFTER this entry call, a held lock,
    its exact live process identity, and the installed source digest.
    """
    root = Path(root)
    source = root / 'ingress_follow.py'
    physical_path(root); physical_path(source)
    started = time.time()
    expected_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    runtime = read_mapping(root / 'environment-runtime.json')
    interpreter = Path(runtime['python_executable'])
    physical_path(interpreter)
    windowless = interpreter.with_name('pythonw.exe')
    physical_path(windowless)
    expected_images = {os.path.normcase(os.path.abspath(x)) for x in (interpreter, windowless)}
    if not lock_is_held(root):
        subprocess.Popen([str(windowless), str(source), '--root', str(root)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status_path = root / 'ingress-follow-status.json'
            physical_path(status_path)
            value = json.loads(status_path.read_text(encoding='utf-8'))
            actual = process_identity(value.get('pid'))
            if valid_follower_status(value, root, started, expected_sha, expected_images,
                                     time.time(), actual, lock_is_held(root)):
                if value.get('state') in ('current', 'applied_waiting_guard_fresh_grant'):
                    return value
                if value.get('state') == 'locked' and value.get('reason') == 'foreign_hold_preserved':
                    raise FollowError('foreign_hold_preserved')
        except FollowError as error:
            if str(error) == 'foreign_hold_preserved':
                raise
        except Exception:
            pass
        time.sleep(.2)
    raise FollowError('ingress_follower_not_ready')


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pipe-snapshot', action='store_true')
    parser.add_argument('--main-dir', type=Path, default=MAIN)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    if args.pipe_snapshot:
        try:
            # This output is captured only by this module, never displayed.
            sys.stdout.buffer.write(json.dumps(main_pipe_snapshot(args.main_dir),
                                                ensure_ascii=True).encode('ascii'))
            return
        except Exception:
            raise SystemExit(2) from None
    # The lock is released by Windows on process death; an owned hold deliberately
    # survives and is re-proved by the next instance before it can be removed.
    import msvcrt
    lock = (args.root / 'ingress-follow.lock').open('a+b')
    lock.seek(0)
    try:
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        raise SystemExit(3) from None
    if os.fstat(lock.fileno()).st_size == 0:
        lock.write(b'0'); lock.flush()
    follower = Follower(args.root, args.main_dir)
    own_identity = process_identity(os.getpid())
    if own_identity is None:
        raise FollowError('follower_identity_unavailable')
    source = args.root / 'ingress_follow.py'
    physical_path(source)
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    while True:
        value = follower.tick()
        value['updated_at'] = time.time()
        value['pid'] = os.getpid()
        value['identity'] = own_identity
        value['source'] = str(source)
        value['source_sha256'] = source_hash
        atomic_json(args.root / 'ingress-follow-status.json', value)
        if args.once:
            print(json.dumps(value, ensure_ascii=False))
            return
        time.sleep(.5)


if __name__ == '__main__':
    run()
