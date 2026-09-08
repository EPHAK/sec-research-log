#!/usr/bin/env python3
"""Recover embedded protobuf FileDescriptorProtos from native binaries.

Descriptors are stored as raw serialized blobs with no length prefix, so we
locate the `name` field (0x0A <len> "....proto") and then walk the wire format
field-by-field to find the exact end of the message.
"""
import sys, re, os
from google.protobuf import descriptor_pb2

# FileDescriptorProto top-level fields -> allowed wire types
FD_FIELDS = {1:{2},2:{2},3:{2},4:{2},5:{2},6:{2},7:{2},8:{2},9:{2},
             10:{0},11:{0},12:{2},13:{2},14:{2}}

def read_varint(data, i):
    val = 0; shift = 0
    for _ in range(10):
        if i >= len(data): return None, i
        b = data[i]; i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80): return val, i
        shift += 7
    return None, i

def message_end(data, start):
    """Walk top-level fields of a FileDescriptorProto; return exact end offset."""
    i = start
    seen_name = False
    while i < len(data):
        tag, j = read_varint(data, i)
        if tag is None: break
        fnum, wt = tag >> 3, tag & 7
        if fnum not in FD_FIELDS or wt not in FD_FIELDS[fnum]:
            break
        if wt == 0:
            v, j = read_varint(data, j)
            if v is None: break
            i = j
        else:
            ln, j = read_varint(data, j)
            if ln is None or j + ln > len(data): break
            if fnum == 1: seen_name = True
            i = j + ln
    return i if seen_name else None

def recover(path):
    data = open(path, 'rb').read()
    found = {}
    for m in re.finditer(rb'\.proto', data):
        end = m.end()
        for back in range(1, 300):
            i = end - back
            if i < 1: break
            if data[i] != 0x0A: continue
            ln, j = read_varint(data, i + 1)
            if ln is None or j + ln != end: continue
            name = data[j:end].decode('utf-8', 'replace')
            if not re.fullmatch(r'[A-Za-z0-9_./-]+\.proto', name): continue
            stop = message_end(data, i)
            if stop is None or stop <= end: break
            fd = descriptor_pb2.FileDescriptorProto()
            try:
                fd.ParseFromString(data[i:stop])
            except Exception:
                break
            if fd.name != name: break
            if not (fd.message_type or fd.enum_type or fd.service or fd.dependency): break
            prev = found.get(fd.name)
            if prev is None or len(fd.SerializeToString()) > len(prev.SerializeToString()):
                found[fd.name] = fd
            break
    return found

def render(fd):
    L = ['syntax = "%s";' % (fd.syntax or 'proto2')]
    if fd.package: L.append('package %s;' % fd.package)
    for d in fd.dependency: L.append('import "%s";' % d)
    L.append('')
    TYPE = {v: k[5:].lower() for k, v in descriptor_pb2.FieldDescriptorProto.Type.items()}
    LABEL = {1:'', 2:'required ', 3:'repeated '}
    def emit_enum(e, ind=''):
        L.append('%senum %s {' % (ind, e.name))
        for v in e.value: L.append('%s  %s = %d;' % (ind, v.name, v.number))
        L.append('%s}' % ind)
    def emit_msg(msg, ind=''):
        maps = {n.name: n for n in msg.nested_type if n.options.map_entry}
        L.append('%smessage %s {' % (ind, msg.name))
        for e in msg.enum_type: emit_enum(e, ind + '  ')
        for n in msg.nested_type:
            if n.options.map_entry: continue
            emit_msg(n, ind + '  ')
        for f in msg.field:
            short = f.type_name.split('.')[-1] if f.type_name else None
            if short in maps:
                me = maps[short]
                kt = TYPE.get(me.field[0].type, '?')
                vf = me.field[1]
                vt = vf.type_name.lstrip('.') if vf.type_name else TYPE.get(vf.type, '?')
                L.append('%s  map<%s, %s> %s = %d;' % (ind, kt, vt, f.name, f.number))
                continue
            t = f.type_name.lstrip('.') if f.type_name else TYPE.get(f.type, '?')
            lbl = LABEL.get(f.label, '')
            if fd.syntax == 'proto3' and f.label == 2: lbl = ''
            L.append('%s  %s%s %s = %d;' % (ind, lbl, t, f.name, f.number))
        L.append('%s}' % ind)
    for e in fd.enum_type: emit_enum(e)
    for msg in fd.message_type: emit_msg(msg)
    for s in fd.service:
        L.append('service %s {' % s.name)
        for mm in s.method:
            L.append('  rpc %s (%s) returns (%s);' % (mm.name, mm.input_type.lstrip('.'), mm.output_type.lstrip('.')))
        L.append('}')
    return '\n'.join(L) + '\n'

if __name__ == '__main__':
    binpath, outdir = sys.argv[1], sys.argv[2]
    found = recover(binpath)
    print("recovered %d descriptors from %s" % (len(found), os.path.basename(binpath)))
    for name, fd in sorted(found.items()):
        dst = os.path.join(outdir, name)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        open(dst, 'w').write(render(fd))
        print("   %-62s %4d msg %4d enum" % (name, len(fd.message_type), len(fd.enum_type)))
