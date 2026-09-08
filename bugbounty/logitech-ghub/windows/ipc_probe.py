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
import argparse, os, socket, sys, time

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
    args = ap.parse_args()

    cts = range(args.scan_types[0], args.scan_types[1] + 1) if args.scan_types else range(0, 17)
    frs = [args.framing] if args.framing else list(FRAMINGS)
    tr = PipeTransport(args.pipe) if args.pipe else TcpTransport(args.host, args.port)

    hits = probe(tr, cts, frs)
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
