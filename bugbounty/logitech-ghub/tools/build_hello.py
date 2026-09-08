#!/usr/bin/env python3
"""Build a logi.updater_ipc HelloRequest envelope, framed for the updater's named pipe."""
import struct, sys

def varint(n):
    out = b''
    while True:
        b = n & 0x7f; n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n: return out

def tag(f, wt): return varint((f << 3) | wt)
def s(f, v):    # length-delimited (string/bytes/message)
    if isinstance(v, str): v = v.encode()
    return tag(f, 2) + varint(len(v)) + v
def u(f, v):    return tag(f, 0) + varint(v)      # varint field
def packed_u32(f, vals):
    body = b''.join(varint(v) for v in vals)
    return tag(f, 2) + varint(len(body)) + body

def endpoint_information(name, identifier, version, pid, exe_path, start_time):
    b = b''
    if name:       b += s(1, name)
    if identifier: b += s(2, identifier)
    if version:    b += s(3, version)
    if pid:        b += u(4, pid)
    if exe_path:   b += s(5, exe_path)
    if start_time: b += u(6, start_time)
    return b

def hello_request(endpoint, language="en-US", protocols=(1,)):
    b = b''
    if endpoint: b += s(1, endpoint)
    if language: b += s(2, language)
    if protocols: b += packed_u32(3, protocols)
    return b

CONTENT_TYPE_HELLO_REQUEST = 0x1100001
FLAG_NONE, FLAG_ERROR, FLAG_EXPECTS_REPLY = 0, 1, 2

def envelope(message_id, content_type, content_data,
             in_response_to_id=0, flags=FLAG_EXPECTS_REPLY):
    b = b''
    if message_id:        b += u(1, message_id)
    if in_response_to_id: b += u(2, in_response_to_id)
    if flags:             b += u(3, flags)
    if content_type:      b += u(4, content_type)
    if content_data:      b += s(5, content_data)
    return b

def frame(env):
    """4-byte little-endian length prefix, then the envelope."""
    return struct.pack('<I', len(env)) + env

def dump(label, data):
    print(f"--- {label}  ({len(data)} bytes) ---")
    print(data.hex())
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        print("  %04x  %-47s  %s" % (
            i, ' '.join(f'{c:02x}' for c in chunk),
            ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)))
    print()

if __name__ == '__main__':
    # ---- A. minimal: no Endpoint sub-message at all
    hr_min = hello_request(endpoint=b'', language="en-US", protocols=(1,))
    env_min = envelope(1, CONTENT_TYPE_HELLO_REQUEST, hr_min)
    dump("A. minimal HelloRequest (inner)", hr_min)
    dump("A. minimal Envelope (unframed)", env_min)
    dump("A. minimal ON THE WIRE (len-prefixed)", frame(env_min))

    # ---- B. realistic: full Endpoint, mimicking lghub_agent
    ep = endpoint_information(
        name="probe", identifier="probe", version="1.0.0",
        pid=1234, exe_path=r"C:\probe\probe.exe", start_time=0)
    hr = hello_request(ep, "en-US", (1,))
    env = envelope(1, CONTENT_TYPE_HELLO_REQUEST, hr)
    dump("B. EndpointInformation", ep)
    dump("B. HelloRequest (inner)", hr)
    dump("B. Envelope (unframed)", env)
    dump("B. ON THE WIRE (len-prefixed)", frame(env))
