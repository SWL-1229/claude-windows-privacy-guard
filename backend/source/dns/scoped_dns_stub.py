"""Loopback-only, scoped DNS-to-DoH candidate. Import and default CLI do nothing.

Only Claude/Anthropic DNS namespaces are forwarded. No default resolver, direct
upstream connection, redirect, or certificate-verification bypass is available.
NRPT installation is separate and requires an administrator.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import http.client
import json
import selectors
import signal
import socket
import ssl
import struct
import threading
import time
import urllib.request

ROOTS = ('claude.ai', 'claude.com', 'anthropic.com', 'claude.app',
         'claudeusercontent.com', 'claudemcpcontent.com')
MAX_QUERY = 4096
MAX_RESPONSE = 65535
MAX_UDP = 4096
DOH_URL = 'https://1.1.1.1/dns-query'


class PacketError(ValueError):
    pass


def read_name(data: bytes, start: int, compressed: bool = True) -> tuple[bytes, int]:
    """Bounds-checked DNS name decoder, rejecting loops and overlong names."""
    labels, offset, end, seen, wire_size = [], start, None, set(), 1
    for _ in range(128):
        if offset >= len(data) or offset in seen:
            raise PacketError('invalid_name')
        seen.add(offset)
        size = data[offset]
        if size & 0xC0 == 0xC0:
            if not compressed or offset + 1 >= len(data):
                raise PacketError('compressed_question_not_supported')
            target = ((size & 0x3F) << 8) | data[offset + 1]
            if target < 12 or target >= offset:
                raise PacketError('invalid_compression_pointer')
            if end is None:
                end = offset + 2
            offset = target
            continue
        if size & 0xC0:
            raise PacketError('invalid_label_type')
        offset += 1
        if size == 0:
            return b'.'.join(labels).lower(), end if end is not None else offset
        if size > 63 or offset + size > len(data):
            raise PacketError('invalid_label')
        wire_size += size + 1
        if wire_size > 255:
            raise PacketError('name_too_long')
        labels.append(data[offset:offset + size])
        offset += size
    raise PacketError('name_hop_limit')


@dataclass(frozen=True)
class Question:
    ident: int
    flags: int
    name: bytes
    qtype: int
    qclass: int
    wire: bytes
    udp_limit: int


def parse_query(data: bytes) -> Question:
    if not 12 <= len(data) <= MAX_QUERY:
        raise PacketError('invalid_query_size')
    ident, flags, qd, an, ns, ar = struct.unpack('!6H', data[:12])
    if flags & ~0x0130 or qd != 1 or an or ns or ar > 1:
        raise PacketError('unsupported_query_header')
    name, offset = read_name(data, 12, compressed=False)
    if not name or offset + 4 > len(data):
        raise PacketError('invalid_question')
    qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
    offset += 4
    if not qtype or qclass != 1:
        raise PacketError('unsupported_question_class')
    question_wire = data[12:offset]
    udp_limit = 512
    if ar:
        owner, after_name = read_name(data, offset, compressed=False)
        if owner or after_name + 10 > len(data):
            raise PacketError('invalid_opt')
        rrtype, payload, ttl, rdlen = struct.unpack('!HHIH', data[after_name:after_name + 10])
        if rrtype != 41 or ttl >> 16 or after_name + 10 + rdlen != len(data):
            raise PacketError('unsupported_opt')
        offset = after_name + 10 + rdlen
        udp_limit = min(MAX_UDP, max(512, payload))
    if offset != len(data):
        raise PacketError('trailing_query_data')
    return Question(ident, flags, name, qtype, qclass, question_wire, udp_limit)


def allowed_name(name: bytes) -> bool:
    try:
        host = name.decode('ascii')
    except UnicodeError:
        return False
    return any(host == root or host.endswith('.' + root) for root in ROOTS)


def error_reply(data: bytes, rcode: int, question: Question | None = None) -> bytes:
    ident = question.ident if question else int.from_bytes(data[:2].ljust(2, b'\0'), 'big')
    rd = (question.flags if question else (int.from_bytes(data[2:4], 'big') if len(data) >= 4 else 0)) & 0x0100
    return struct.pack('!6H', ident, 0x8080 | rd | rcode, 1 if question else 0, 0, 0, 0) + (question.wire if question else b'')


def validate_response(response: bytes, question: Question) -> bytes:
    if not 12 <= len(response) <= MAX_RESPONSE:
        raise PacketError('invalid_response_size')
    ident, flags, qd, an, ns, ar = struct.unpack('!6H', response[:12])
    if ident != question.ident or not flags & 0x8000 or flags & 0x7840 or qd != 1 or an + ns + ar > 512:
        raise PacketError('invalid_response_header')
    name, offset = read_name(response, 12)
    if offset + 4 > len(response):
        raise PacketError('truncated_response_question')
    qt, qc = struct.unpack('!HH', response[offset:offset + 4])
    offset += 4
    if (name, qt, qc) != (question.name, question.qtype, question.qclass):
        raise PacketError('response_question_mismatch')
    for _ in range(an + ns + ar):
        _, offset = read_name(response, offset)
        if offset + 10 > len(response):
            raise PacketError('truncated_resource_record')
        rdlen = struct.unpack_from('!H', response, offset + 8)[0]
        offset += 10 + rdlen
        if offset > len(response):
            raise PacketError('truncated_resource_data')
    if offset != len(response):
        raise PacketError('trailing_response_data')
    return response


def truncate_udp(response: bytes, question: Question) -> bytes:
    # A TC response intentionally contains only the echoed question; the client
    # must retry TCP. It never contains a partial resource record.
    flags = struct.unpack_from('!H', response, 2)[0] | 0x0200
    return struct.pack('!6H', question.ident, flags, 1, 0, 0, 0) + question.wire


class StrictProxyHandler(urllib.request.ProxyHandler):
    """Do not allow NO_PROXY or environment settings to bypass the gateway."""
    def proxy_open(self, req, proxy, type):
        if req.type != 'https' or req.full_url != DOH_URL:
            raise OSError('unexpected_upstream_destination')
        req.set_proxy(proxy.removeprefix('http://'), 'http')
        return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def connection_factory(gateway_port: int):
    class GatewayHTTPSConnection(http.client.HTTPSConnection):
        def cancel_deadline(self):
            timer = getattr(self, '_deadline_timer', None)
            if timer:
                timer.cancel()
            lock = getattr(self, '_deadline_lock', None)
            if lock:
                with lock:
                    channel = self._deadline_channel
                    self._deadline_channel = None
                if channel:
                    channel.close()

        def expire_deadline(self):
            # A duplicate of the raw socket shares the same TCP connection. It
            # can interrupt TLS/read even after urllib hands the original socket
            # to HTTPResponse's file object. Never refer to a recycled raw FD.
            with self._deadline_lock:
                channel = self._deadline_channel
                self._deadline_channel = None
            if channel:
                try:
                    channel.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                finally:
                    channel.close()

        def connect(self):
            if self.host != '127.0.0.1' or self.port != gateway_port or self._tunnel_host != '1.1.1.1' or self._tunnel_port != 443:
                raise OSError('direct_or_unexpected_upstream_forbidden')
            channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            channel.settimeout(self.timeout)
            self.sock = channel
            self._deadline_lock = threading.Lock()
            self._deadline_channel = channel.dup()
            self._deadline_timer = threading.Timer(self.timeout, self.expire_deadline)
            self._deadline_timer.daemon = True
            self._deadline_timer.start()
            try:
                # Numeric AF_INET connect, deliberately no socket.create_connection
                # or getaddrinfo. The literal upstream is sent in CONNECT.
                channel.connect(('127.0.0.1', gateway_port))
                self._tunnel()
                self.sock = self._context.wrap_socket(channel, server_hostname='1.1.1.1')
            except BaseException:
                self.cancel_deadline()
                channel.close()
                raise
    return GatewayHTTPSConnection


class GatewayHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, port):
        super().__init__(context=ssl.create_default_context())
        self.connection = connection_factory(port)

    def https_open(self, req):
        connections = []
        def construct(*args, **kwargs):
            connection = self.connection(*args, **kwargs)
            connections.append(connection)
            return connection
        try:
            reply = self.do_open(construct, req, context=self._context)
            reply._scoped_dns_cancel_deadline = connections[0].cancel_deadline
            return reply
        except BaseException:
            for connection in connections:
                connection.cancel_deadline()
            raise


class DoHClient:
    def __init__(self, gateway_port=17894, timeout=7):
        if type(gateway_port) is not int or not 1 <= gateway_port <= 65535 or not 0 < timeout <= 8:
            raise ValueError('invalid_upstream_parameters')
        self.timeout = timeout
        proxy = f'http://127.0.0.1:{gateway_port}'
        self.opener = urllib.request.build_opener(StrictProxyHandler({'https': proxy, 'http': proxy}),
                                                  GatewayHTTPSHandler(gateway_port), NoRedirect())

    def query(self, message: bytes) -> bytes:
        req = urllib.request.Request(DOH_URL, data=message, method='POST', headers={
            'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message',
            'User-Agent': 'Claude-Scoped-DNS/1', 'Cache-Control': 'no-store'})
        reply = None
        try:
            with self.opener.open(req, timeout=self.timeout) as reply:
                if reply.status != 200 or reply.headers.get_content_type() != 'application/dns-message':
                    raise OSError('invalid_doh_response')
                data = reply.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise OSError('oversized_doh_response')
                return data
        finally:
            cancel = getattr(reply, '_scoped_dns_cancel_deadline', None)
            if cancel:
                cancel()


class Resolver:
    def __init__(self, upstream):
        self.upstream = upstream
        self.counters = {}
        self.lock = threading.Lock()

    def count(self, key):
        with self.lock:
            self.counters[key] = self.counters.get(key, 0) + 1

    def snapshot(self):
        with self.lock:
            return dict(self.counters)

    def answer(self, data: bytes, udp=True) -> bytes:
        self.count('received')
        try:
            question = parse_query(data)
        except PacketError:
            self.count('formerr')
            return error_reply(data, 1)
        if not allowed_name(question.name):
            self.count('refused')
            return error_reply(data, 5, question)
        try:
            response = validate_response(self.upstream.query(data), question)
            self.count('upstream_validated')
            if udp and len(response) > question.udp_limit:
                self.count('truncated')
                return truncate_udp(response, question)
            return response
        except Exception:
            self.count('servfail')
            return error_reply(data, 2, question)


def receive_exact(channel, count, deadline=None):
    deadline = time.monotonic() + 8 if deadline is None else deadline
    chunks = bytearray()
    while len(chunks) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('tcp_frame_deadline')
        channel.settimeout(remaining)
        piece = channel.recv(count - len(chunks))
        if not piece:
            raise OSError('incomplete_tcp_frame')
        chunks.extend(piece)
    return bytes(chunks)


def serve(port=53, gateway_port=17894, workers=8, stop_event=None, on_ready=None):
    if type(port) is not int or not 1 <= port <= 65535 or not 1 <= workers <= 16:
        raise ValueError('invalid_listener_parameters')
    stop = stop_event or threading.Event()
    resolver = Resolver(DoHClient(gateway_port))
    capacity = threading.BoundedSemaphore(workers * 2)
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='scoped-dns')
    selector = selectors.DefaultSelector()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    def udp_task(data, address):
        try:
            udp.sendto(resolver.answer(data), address)
        except OSError:
            resolver.count('send_error')
        finally:
            capacity.release()
    def tcp_task(channel):
        try:
            with channel:
                # All clients are local: allow one second for the complete frame
                # and seven seconds for the single DoH request, no slow drip.
                deadline = time.monotonic() + 1
                size = struct.unpack('!H', receive_exact(channel, 2, deadline))[0]
                if not 12 <= size <= MAX_QUERY:
                    raise PacketError('invalid_tcp_frame_size')
                response = resolver.answer(receive_exact(channel, size, deadline), udp=False)
                channel.sendall(struct.pack('!H', len(response)) + response)
        except (OSError, PacketError):
            resolver.count('tcp_error')
        finally:
            capacity.release()
    try:
        # No SO_REUSEADDR: a second process must not share the listening endpoint.
        udp.bind(('127.0.0.1', port))
        tcp.bind(('127.0.0.1', port))
        tcp.listen(workers * 2)
        udp.setblocking(False)
        tcp.setblocking(False)
        selector.register(udp, selectors.EVENT_READ, 'udp')
        selector.register(tcp, selectors.EVENT_READ, 'tcp')
        print(json.dumps({'status': 'ready', 'bind': 'loopback_only', 'port': port,
                          'namespaces': len(ROOTS), 'workers': workers}), flush=True)
        if on_ready is not None:
            on_ready()
        while not stop.is_set():
            for key, _ in selector.select(timeout=.25):
                if key.data == 'udp':
                    try:
                        data, address = udp.recvfrom(MAX_QUERY + 1)
                    except (ConnectionResetError, BlockingIOError):
                        # Windows reports late ICMP from a closed local DNS client
                        # on recvfrom; this must not stop the shared resolver.
                        resolver.count('udp_client_closed_or_retry')
                        continue
                    if capacity.acquire(blocking=False):
                        pool.submit(udp_task, data, address)
                    else:
                        resolver.count('overloaded')
                        udp.sendto(error_reply(data, 2), address)
                else:
                    channel, _ = tcp.accept()
                    if capacity.acquire(blocking=False):
                        pool.submit(tcp_task, channel)
                    else:
                        resolver.count('overloaded')
                        channel.close()
    finally:
        selector.close()
        # Keep UDP open until queued work has drained, at most the bounded
        # upstream timeouts. No authentication or DNS query logs are retained.
        pool.shutdown(wait=True, cancel_futures=True)
        udp.close()
        tcp.close()
        print(json.dumps({'status': 'stopped', 'counts': resolver.snapshot()}), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve', action='store_true', help='explicitly start loopback UDP/TCP DNS')
    parser.add_argument('--port', type=int, default=53)
    parser.add_argument('--gateway-port', type=int, default=17894)
    parser.add_argument('--workers', type=int, default=8)
    args = parser.parse_args(argv)
    if not args.serve:
        parser.print_help()
        return 0
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    serve(args.port, args.gateway_port, args.workers, stop)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
