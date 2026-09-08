#!/usr/bin/env python3
"""
Logitech G HUB updater IPC prober.

Purpose: determine whether an ORDINARY, UNSIGNED, NON-ELEVATED process can complete the
updater IPC handshake with lghub_updater.exe (which runs as SYSTEM).

Run this as a normal user, from a plain `python.exe` - do NOT sign it, do NOT run as admin.
That is the entire test: if a HelloResponse comes back, the SYSTEM service accepted an
unverified client.

Read-only: sends only HelloRequest / Ping. It does NOT call any state-changing method.
Stdlib only - no pip installs needed on the Windows box.

Usage:
  python ipc_probe.py                          # probe TCP 127.0.0.1:9180
  python ipc_probe.py --port 9180
  python ipc_probe.py --pipe logi.updater_ipc  # probe a named pipe instead
  python ipc_probe.py --scan-types 0 64        # enumerate content_type values
"""
import argparse, base64, hashlib, os, socket, sys, time

# ---------- minimal protobuf wire encoder (stdlib only) ----------

def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)

def tag(field, wire):
    return varint((field << 3) | wire)

def f_varint(field, value):
    return b"" if not value else tag(field, 0) + varint(value)

def f_bytes(field, value):
    if not value:
        return b""
    if isinstance(value, str):
        value = value.encode()
    return tag(field, 2) + varint(len(value)) + value

def read_varint(buf, i):
    val = 0; shift = 0
    while i < len(buf):
        b = buf[i]; i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7
    return None, i

def dump_proto(buf, indent="    "):
    """Best-effort pretty-print of an unknown protobuf message."""
    out, i = [], 0
    while i < len(buf):
        t, i = read_varint(buf, i)
        if t is None: break
        fn, wt = t >> 3, t & 7
        if wt == 0:
            v, i = read_varint(buf, i)
            out.append("%sfield %d varint = %s" % (indent, fn, v))
        elif wt == 2:
            ln, i = read_varint(buf, i)
            if ln is None or i + ln > len(buf): break
            raw = buf[i:i+ln]; i += ln
            try:
                s = raw.decode("utf-8")
                printable = all(31 < ord(c) < 127 or c in "\t\n" for c in s)
            except UnicodeDecodeError:
                printable = False
            if printable and raw:
                out.append('%sfield %d str    = "%s"' % (indent, fn, s))
            else:
                out.append("%sfield %d bytes[%d]" % (indent, fn, len(raw)))
                out.extend(dump_proto(raw, indent + "  "))
        elif wt == 5:
            i += 4; out.append("%sfield %d fixed32" % (indent, fn))
        elif wt == 1:
            i += 8; out.append("%sfield %d fixed64" % (indent, fn))
        else:
            break
    return out

# ---------- G HUB messages ----------

def endpoint_information(name, identifier, version, pid, exe_path, start_time=0):
    return (f_bytes(1, name) + f_bytes(2, identifier) + f_bytes(3, version) +
            f_varint(4, pid) + f_bytes(5, exe_path) + f_varint(6, start_time))

def hello_request(name="probe", identifier="probe", version="1.0",
                  pid=None, exe_path=None, protocols=(1,)):
    """HelloRequest. Every identity field here is CLIENT-SUPPLIED - that is the point."""
    if pid is None:
        pid = os.getpid()
    if exe_path is None:
        exe_path = sys.executable
    ep = endpoint_information(name, identifier, version, pid, exe_path)
    body = f_bytes(1, ep) + f_bytes(2, "en")
    for p in protocols:
        body += f_varint(3, p)
    return body

def envelope(message_id, content_type, content_data, flags=2):
    # flags 2 = EXPECTS_REPLY
    return (f_varint(1, message_id) + f_varint(3, flags) +
            f_varint(4, content_type) + f_bytes(5, content_data))

# ---------- framings ----------

FRAMINGS = {
    "raw":        lambda b: b,
    "len32be":    lambda b: len(b).to_bytes(4, "big") + b,
    "len32le":    lambda b: len(b).to_bytes(4, "little") + b,
    "varintlen":  lambda b: varint(len(b)) + b,
    "http_post":  lambda b: (b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                             b"Content-Type: application/x-protobuf\r\n"
                             b"Content-Length: " + str(len(b)).encode() +
                             b"\r\nConnection: close\r\n\r\n" + b),
}

# ---------- minimal WebSocket client (stdlib only) ----------

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# subprotocols recovered from the binaries
SUBPROTOCOLS = [
    "logi.updater_ipc.protocol.v1.protobuf",
    "logi.updater_ipc.protocol.protobuf",
    None,
]
WS_PATHS = ["/", "/ipc", "/updater", "/v1"]

def ws_frame(payload, opcode=2):
    """Client -> server frame. Client frames MUST be masked (RFC 6455 5.3)."""
    fin_op = 0x80 | opcode
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        hdr = bytes([fin_op, 0x80 | n])
    elif n < 65536:
        hdr = bytes([fin_op, 0x80 | 126]) + n.to_bytes(2, "big")
    else:
        hdr = bytes([fin_op, 0x80 | 127]) + n.to_bytes(8, "big")
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return hdr + mask + masked

def ws_parse(buf):
    """Parse as many complete frames as possible. -> ([(opcode, payload)], leftover)"""
    frames, i = [], 0
    while i + 2 <= len(buf):
        b0, b1 = buf[i], buf[i + 1]
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        ln = b1 & 0x7F
        j = i + 2
        if ln == 126:
            if j + 2 > len(buf): break
            ln = int.from_bytes(buf[j:j+2], "big"); j += 2
        elif ln == 127:
            if j + 8 > len(buf): break
            ln = int.from_bytes(buf[j:j+8], "big"); j += 8
        mask = b""
        if masked:
            if j + 4 > len(buf): break
            mask = buf[j:j+4]; j += 4
        if j + ln > len(buf): break
        payload = buf[j:j+ln]
        if mask:
            payload = bytes(c ^ mask[k % 4] for k, c in enumerate(payload))
        frames.append((opcode, payload))
        i = j + ln
    return frames, buf[i:]

def ws_handshake(sock, host, port, path="/", subprotocol=None, origin=None):
    """Returns (ok, status_line, raw_headers, leftover_bytes)."""
    key = base64.b64encode(os.urandom(16)).decode()
    req = ("GET %s HTTP/1.1\r\n" % path +
           "Host: %s:%d\r\n" % (host, port) +
           "Upgrade: websocket\r\n" +
           "Connection: Upgrade\r\n" +
           "Sec-WebSocket-Key: %s\r\n" % key +
           "Sec-WebSocket-Version: 13\r\n")
    if subprotocol:
        req += "Sec-WebSocket-Protocol: %s\r\n" % subprotocol
    if origin:
        req += "Origin: %s\r\n" % origin
    req += "\r\n"
    sock.sendall(req.encode())

    buf = b""
    deadline = time.time() + 3
    while b"\r\n\r\n" not in buf and time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    if b"\r\n\r\n" not in buf:
        return False, "<no response>", b"", b""
    head, leftover = buf.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n")[0].decode("latin1")
    if b" 101 " not in head[:32]:
        return False, status, head, leftover
    expect = base64.b64encode(
        hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    if expect.encode().lower() not in head.lower():
        return False, status + "  (bad Sec-WebSocket-Accept)", head, leftover
    return True, status, head, leftover

def probe_websocket(host, port, content_types):
    """Try a WebSocket upgrade, then speak Envelope over binary frames."""
    print("=" * 72)
    print("Probing WebSocket on %s:%d" % (host, port))
    print("=" * 72)
    hits = []
    for path in WS_PATHS:
        for sp in SUBPROTOCOLS:
            try:
                s = socket.create_connection((host, port), timeout=3)
                s.settimeout(2.5)
            except Exception as e:
                print("  [!] connect failed: %s" % e)
                return hits
            try:
                ok, status, head, leftover = ws_handshake(s, host, port, path, sp)
                label = "path=%-9s subprotocol=%s" % (path, sp or "<none>")
                if not ok:
                    print("  %-58s -> %s" % (label, status))
                    continue
                print("\n  *** UPGRADED  %s" % label)
                print("      %s" % status)
                for line in head.decode("latin1").split("\r\n")[1:]:
                    if line.lower().startswith("sec-websocket-protocol"):
                        print("      %s" % line)

                # anything the server pushes unprompted (45654 does exactly this)
                pending = leftover
                try:
                    pending += s.recv(65535)
                except socket.timeout:
                    pass
                frames, pending = ws_parse(pending)
                for op, pl in frames:
                    print("      <- unsolicited frame opcode=%d (%d bytes)" % (op, len(pl)))
                    for l in dump_proto(pl)[:20]:
                        print("      " + l)

                # now speak Envelope
                for ct in content_types:
                    env = envelope(1, ct, hello_request())
                    try:
                        s.sendall(ws_frame(env))
                        raw = s.recv(65535)
                    except Exception:
                        raw = b""
                    if not raw:
                        continue
                    fr, _ = ws_parse(raw)
                    for op, pl in fr:
                        if op == 8:
                            print("      <- close frame after content_type=%d" % ct)
                            continue
                        print("\n      *** REPLY content_type=%d (%d bytes)" % (ct, len(pl)))
                        for l in dump_proto(pl)[:25]:
                            print("      " + l)
                        hits.append((path, sp, ct, pl))
            finally:
                try: s.close()
                except Exception: pass
    return hits

# ---------- transports ----------

class TcpTransport:
    def __init__(self, host, port):
        self.host, self.port = host, port
    def open(self):
        s = socket.create_connection((self.host, self.port), timeout=3)
        s.settimeout(2.5)
        return s
    def close(self, s):
        try: s.close()
        except Exception: pass
    def send(self, s, data): s.sendall(data)
    def recv(self, s):
        try: return s.recv(65535)
        except socket.timeout: return b""
    def label(self): return "tcp %s:%d" % (self.host, self.port)

class PipeTransport:
    """Named pipe via ctypes CreateFileW - no pywin32 needed."""
    def __init__(self, name):
        self.name = name if name.startswith("\\\\") else r"\\.\pipe" + "\\" + name
    def open(self):
        import ctypes
        from ctypes import wintypes
        k = ctypes.windll.kernel32
        k.CreateFileW.restype = wintypes.HANDLE
        h = k.CreateFileW(self.name, 0xC0000000, 0, None, 3, 0, None)
        if h == wintypes.HANDLE(-1).value:
            raise OSError("CreateFileW failed: %d" % ctypes.get_last_error())
        return h
    def close(self, h):
        import ctypes
        ctypes.windll.kernel32.CloseHandle(h)
    def send(self, h, data):
        import ctypes
        from ctypes import wintypes
        n = wintypes.DWORD(0)
        ctypes.windll.kernel32.WriteFile(h, data, len(data), ctypes.byref(n), None)
    def recv(self, h):
        import ctypes
        from ctypes import wintypes
        buf = ctypes.create_string_buffer(65535)
        n = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.ReadFile(h, buf, 65535, ctypes.byref(n), None)
        return buf.raw[:n.value] if ok else b""
    def label(self): return "pipe %s" % self.name

# ---------- probe ----------

def probe(transport, content_types, framings):
    print("=" * 72)
    print("Probing %s" % transport.label())
    print("  process: pid=%d exe=%s" % (os.getpid(), sys.executable))
    print("=" * 72)
    hello = hello_request()
    hits = []
    for ct in content_types:
        for fname in framings:
            frame = FRAMINGS[fname]
            payload = frame(envelope(1, ct, hello))
            try:
                conn = transport.open()
            except Exception as e:
                print("  [!] cannot connect: %s" % e)
                return hits
            try:
                transport.send(conn, payload)
                resp = transport.recv(conn)
            except Exception:
                resp = b""
            finally:
                transport.close(conn)
            if resp:
                head = resp[:16].hex()
                print("\n  *** RESPONSE  content_type=%d framing=%s  (%d bytes)" %
                      (ct, fname, len(resp)))
                print("      head: %s" % head)
                if resp[:5] in (b"HTTP/",):
                    first = resp.split(b"\r\n")[0].decode("latin1")
                    print("      http: %s" % first)
                    if b" 404 " in resp[:40] or b" 400 " in resp[:40]:
                        continue          # generic rejection, not a real hit
                else:
                    for line in dump_proto(resp)[:25]:
                        print("      " + line)
                hits.append((ct, fname, resp))
            time.sleep(0.02)
    return hits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9180)
    ap.add_argument("--pipe", default=None)
    ap.add_argument("--scan-types", nargs=2, type=int, metavar=("LO", "HI"))
    ap.add_argument("--framing", default=None, choices=list(FRAMINGS))
    ap.add_argument("--ws", action="store_true", help="WebSocket only")
    args = ap.parse_args()

    cts = range(args.scan_types[0], args.scan_types[1] + 1) if args.scan_types else range(0, 17)
    frs = [args.framing] if args.framing else list(FRAMINGS)
    if args.ws:
        hits = probe_websocket(args.host, args.port, cts)
    else:
        tr = PipeTransport(args.pipe) if args.pipe else TcpTransport(args.host, args.port)
        hits = probe(tr, cts, frs)
        if not hits and not args.pipe:
            print("\n  no raw-framing response; trying a WebSocket upgrade "
                  "(the updater links websocketpp)\n")
            hits = probe_websocket(args.host, args.port, cts)
    print("\n" + "=" * 72)
    if hits:
        print("RESULT: %d response(s). If any decoded as protobuf with an" % len(hits))
        print("in_response_to_id / EndpointInformation, the SYSTEM service ACCEPTED")
        print("an unsigned, non-elevated, client-declared identity. That is the finding.")
    else:
        print("RESULT: no responses. Either this is not the IPC transport, or the")
        print("handshake was rejected. Capture the real agent traffic (step 3) before")
        print("concluding the endpoint is authenticated.")
    print("=" * 72)

if __name__ == "__main__":
    main()
