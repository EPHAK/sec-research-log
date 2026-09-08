#!/usr/bin/env python3
"""Decode a self-relative Windows SECURITY_DESCRIPTOR (as returned by
getfattr -n system.ntfs_acl on ntfs-3g) and print the DACL in a readable form,
focused on whether non-admin principals can create files vs. just folders."""
import struct, sys

WELL_KNOWN = {
    "S-1-1-0": "Everyone",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-18": "SYSTEM (LocalSystem)",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-4": "INTERACTIVE",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-1": "CREATOR GROUP",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": "NT SERVICE\\TrustedInstaller",
    "S-1-15-2-1": "ALL APPLICATION PACKAGES",
    "S-1-15-2-2": "ALL RESTRICTED APPLICATION PACKAGES",
    "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
}

def parse_sid(data, off):
    rev = data[off]
    sub_count = data[off+1]
    auth = int.from_bytes(data[off+2:off+8], 'big')
    subs = struct.unpack_from(f'<{sub_count}I', data, off+8)
    sid = f"S-{rev}-{auth}" + ''.join(f"-{s}" for s in subs)
    length = 8 + 4*sub_count
    return sid, length

# generic + file-specific access mask bits that matter for "can I create a FILE here"
MASK_BITS = [
    (0x00000001, "FILE_LIST_DIRECTORY / FILE_READ_DATA"),
    (0x00000002, "FILE_ADD_FILE (create a FILE in this dir)"),          # <-- the one that matters
    (0x00000004, "FILE_ADD_SUBDIRECTORY (create a FOLDER in this dir)"),# <-- NOT the same thing
    (0x00000008, "FILE_READ_EA"),
    (0x00000010, "FILE_WRITE_EA"),
    (0x00000020, "FILE_TRAVERSE / FILE_EXECUTE"),
    (0x00000040, "FILE_DELETE_CHILD"),
    (0x00000080, "FILE_READ_ATTRIBUTES"),
    (0x00000100, "FILE_WRITE_ATTRIBUTES"),
    (0x00010000, "DELETE"),
    (0x00020000, "READ_CONTROL"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x10000000, "GENERIC_ALL"),
    (0x20000000, "GENERIC_EXECUTE"),
    (0x40000000, "GENERIC_WRITE"),
    (0x80000000, "GENERIC_READ"),
]

ACE_TYPES = {0: "ALLOW", 1: "DENY", 2: "AUDIT", 5: "ALLOW(OBJECT)", 6: "DENY(OBJECT)"}

def decode(data):
    rev, sbz1, control = struct.unpack_from('<BBH', data, 0)
    off_owner, off_group, off_sacl, off_dacl = struct.unpack_from('<IIII', data, 4)
    print(f"revision={rev} control={control:#06x}  DACL_PRESENT={bool(control & 0x0004)}  SE_DACL_AUTO_INHERITED={bool(control & 0x0400)}")

    owner_sid, _ = parse_sid(data, off_owner) if off_owner else (None, 0)
    group_sid, _ = parse_sid(data, off_group) if off_group else (None, 0)
    print(f"owner: {owner_sid}  ({WELL_KNOWN.get(owner_sid,'?')})")
    print(f"group: {group_sid}  ({WELL_KNOWN.get(group_sid,'?')})")

    if not off_dacl:
        print("NO DACL -> unrestricted access to everyone (this would itself be the finding)")
        return
    acl_off = off_dacl
    acl_rev, sbz1b, acl_size, ace_count, sbz2 = struct.unpack_from('<BBHHH', data, acl_off)
    print(f"\nDACL: {ace_count} ACEs, size {acl_size} bytes\n")
    p = acl_off + 8
    for i in range(ace_count):
        ace_type, ace_flags, ace_size = struct.unpack_from('<BBH', data, p)
        mask = struct.unpack_from('<I', data, p+4)[0]
        sid, sidlen = parse_sid(data, p+8)
        name = WELL_KNOWN.get(sid, sid)
        kind = ACE_TYPES.get(ace_type, f"TYPE{ace_type}")
        inherit_only = bool(ace_flags & 0x08)
        object_inherit = bool(ace_flags & 0x01)
        container_inherit = bool(ace_flags & 0x02)
        print(f"[{i}] {kind:14s} {name:32s} mask={mask:#010x}  "
              f"OI={int(object_inherit)} CI={int(container_inherit)} InheritOnly={int(inherit_only)}")
        set_bits = [desc for bit, desc in MASK_BITS if mask & bit]
        for d in set_bits:
            print(f"       {d}")
        p += ace_size
    print()

if __name__ == '__main__':
    hexstr = sys.argv[1]
    data = bytes.fromhex(hexstr[2:] if hexstr.startswith('0x') else hexstr)
    decode(data)
