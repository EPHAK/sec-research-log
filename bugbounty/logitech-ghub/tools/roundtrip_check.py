#!/usr/bin/env python3
"""Parse the generated HelloRequest frame using the descriptors embedded in
lghub_updater.exe itself - not a hand-written .proto. Independent check that the
field numbers and the envelope layout are right."""
import sys, os
sys.path.insert(0, os.environ.get('LOGI_DIR','/home/ephak/research/logitech'))
sys.path.insert(0, os.path.join(os.environ.get('LOGI_DIR','/home/ephak/research/logitech'),'handoff'))
from extract_protos import read_varint, message_end
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from build_hello import (endpoint_information, hello_request, envelope, frame,
                         CONTENT_TYPE_HELLO_REQUEST, FLAG_EXPECTS_REPLY)
import struct

data = open(os.path.join(os.environ.get('LOGI_DIR','/home/ephak/research/logitech'),'bin/lghub_updater.exe'),'rb').read()

WANT = ['logi/updater_ipc/protocol/messages/envelope.proto',
        'logi/updater_ipc/protocol/messages/v1/connections.proto']
found = {}
for want in WANT:
    needle = bytes([0x0A, len(want)]) + want.encode()
    i = data.find(needle)
    while i != -1 and want not in found:
        end = message_end(data, i)
        if end and end > i:
            blob = data[i:end]
            fdp = descriptor_pb2.FileDescriptorProto()
            try:
                fdp.ParseFromString(blob)
                if fdp.name == want and fdp.message_type:
                    found[want] = fdp
                    break
            except Exception:
                pass
        i = data.find(needle, i+1)

for w in WANT:
    if w not in found:
        print(f"!! could not recover {w}"); sys.exit(1)
    print(f"recovered {w}: messages = {[m.name for m in found[w].message_type]}")

pool = descriptor_pool.DescriptorPool()
for w in WANT:
    pool.Add(found[w])

Envelope = message_factory.GetMessageClass(
    pool.FindMessageTypeByName('logi.updater_ipc.protocol.protobuf.Envelope'))
HelloRequest = message_factory.GetMessageClass(
    pool.FindMessageTypeByName('logi.updater_ipc.protocol.v1.protobuf.HelloRequest'))

# rebuild the exact frame the PowerShell probe sends (realistic variant)
ep = endpoint_information("probe","probe","1.0.0",1234,r"C:\probe\probe.exe",0)
hr = hello_request(ep, "en-US", (1,))
env = envelope(1, CONTENT_TYPE_HELLO_REQUEST, hr, flags=FLAG_EXPECTS_REPLY)
wire = frame(env)

print(f"\nframe = {len(wire)} bytes; prefix says {struct.unpack('<I', wire[:4])[0]}, "
      f"body is {len(wire)-4}  -> {'OK' if struct.unpack('<I',wire[:4])[0]==len(wire)-4 else 'MISMATCH'}")

e = Envelope(); n = e.ParseFromString(wire[4:])
print("\n--- Envelope parsed with the binary's own descriptor ---")
print(e)
print("content_type == 0x1100001 ?", e.content_type == 0x1100001)
print("flags        == EXPECTS_REPLY ?", e.flags == 2)

h = HelloRequest(); h.ParseFromString(e.content_data)
print("--- content_data parsed as HelloRequest ---")
print(h)
print("SupportedProtocols ==", list(h.SupportedProtocols))
assert e.content_type == 0x1100001
assert list(h.SupportedProtocols) == [1]
assert h.Language == "en-US"
assert h.Endpoint.Name == "probe"
print("\nALL ASSERTIONS PASSED - the frame is well-formed against the shipped schema.")
