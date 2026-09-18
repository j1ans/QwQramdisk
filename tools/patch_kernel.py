#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path

from .common import patch_bytes, write_manifest
from .lzss import pack, unpack
from .offsetfinder import (MOV_W8_3, NOP, MachOArm64, branch_target,
                           encode_b, encode_bl, find_all, find_unique, is_cb,
                           read_word)


AES_HANDLE_SIG = bytes.fromhex("682640b91fa10f71")
ART_FLOW_SIG = bytes.fromhex(
    "7f820739880240f9081540f9e00314aa00013fd6"
    "68da40f9680900b468ea40f9a80100b5")
IOS7_UID_NATIVE_SIG = bytes.fromhex(
    "88028052bf421f7100020054bfa60f7161000054")
IOS7_ART_FLOW_SIG = bytes.fromhex(
    "68da40f9880b00b468ea40f9880100b5")
IOS7_SECURE_ROOT_TRUST_SIG = bytes.fromhex(
    # Result of strncmp(root-name, candidate, strlen(root-name)), followed by
    # the SecureRoot trust byte and readiness byte stores.
    "e80300aa602a04911f010031e8179f1a"
    "68320439e8030032682a0439")
IOS7_USERCLIENT_DERIVED_REJECT_SIG = bytes.fromhex(
    # SUB W8, W8, #0x898; MOV W26, #kIOReturnUnsupported;
    # CMP W8, #0x64.  The following B.CC rejects the complete derived-handle
    # range before the wrapper can construct memory descriptors and enter the
    # normal +0x548 provider method.
    "08612251faffa3123a5880721f910171")
MOV_W8_1 = bytes.fromhex("28008052")


def extract_source(data):
    if data[:4] == b"\xcf\xfa\xed\xfe":
        return "macho", None, data, b""
    magic = data.find(b"complzss")
    if magic < 0:
        raise ValueError("cannot find Mach-O or complzss payload")
    info, macho = unpack(data[magic:])
    end = magic + 0x180 + info["csize"]
    return "complzss", info, macho, data[end:]


def _find_boot_arg_ref(finder, name, validator):
    matches = []
    for ref, string_off, string_va in finder.string_refs(name):
        if validator(ref):
            matches.append((ref, string_off, string_va))
    if len(matches) != 1:
        raise ValueError(f"{name.decode()} boot-arg XREF: expected one contextual match, got {len(matches)}")
    return matches[0]


def locate(kernel):
    if b"Darwin Kernel Version 14." not in kernel:
        raise ValueError("kernel is not from the supported Darwin 14 family")
    ios7 = b"root:xnu-2423." in kernel
    finder = MachOArm64(kernel)

    def debug_context(ref):
        ios8_layout = kernel[ref + 8:ref + 16] == bytes.fromhex(
            "e1830191e2031e32")
        ios7_layout = (kernel[ref + 8:ref + 12]
                       == bytes.fromhex("e2031e32")
                       and read_word(kernel, ref + 12) & 0xFFE0FFFF
                       == 0xAA0003E1)
        return ((ios8_layout or ios7_layout)
                and is_cb(read_word(kernel, ref + 20))
                and read_word(kernel, ref + 28) & 0x7F000000 == 0x36000000)

    debug_ref, debug_string, _ = _find_boot_arg_ref(finder, b"debug", debug_context)
    debug_branch = debug_ref + 20
    debug_bit = debug_ref + 28

    def serial_context(ref):
        if kernel[ref + 8:ref + 12] != bytes.fromhex("e2031e32"):
            return False
        load = read_word(kernel, ref + 16)
        test = read_word(kernel, ref + 20)
        return (load & 0xFFC00000 == 0x39400000 and load & 31 == 8
                and test & 0x7F000000 == 0x36000000 and test & 31 == 8)

    serial_ref, serial_string, _ = _find_boot_arg_ref(finder, b"serial", serial_context)
    serial_load = serial_ref + 16
    serial_test = serial_ref + 20
    load_word = read_word(kernel, serial_load)
    serial_store = (load_word & ~0x00400000).to_bytes(4, "little")

    aes_branch = None
    secure_root_trust = None
    if ios7:
        # The 7.1 SmartIOAES implementation maps 0x7d0 directly to the UID
        # selection (0x14).  Patching its branch would weaken the correct path.
        native_uid = find_all(kernel, IOS7_UID_NATIVE_SIG)
        if len(native_uid) != 2:
            raise ValueError(
                "native iOS 7 UID AES dispatch: expected isKeySupported and "
                f"keySelection matches, got {len(native_uid)}")
        trust = find_unique(kernel, IOS7_SECURE_ROOT_TRUST_SIG,
                            "iOS 7 SecureRoot name trust result")
        secure_root_trust = trust + 12
        trust_va = finder.offset_to_va(trust)
        name_refs = [ref for ref, _off, _va
                     in finder.string_refs(b"SecureRootName")
                     if trust_va - 0x100 <= finder.offset_to_va(ref)
                     <= trust_va + 0x100]
        if len(name_refs) != 1:
            raise ValueError("iOS 7 SecureRoot trust result has no unique "
                             "SecureRootName XREF context")
        derived_reject = find_unique(
            kernel, IOS7_USERCLIENT_DERIVED_REJECT_SIG,
            "iOS 7 IOAES derived-handle user-client rejection")
        derived_reject_branch = derived_reject + len(
            IOS7_USERCLIENT_DERIVED_REJECT_SIG)
        if read_word(kernel, derived_reject_branch) & 0xFF000010 != 0x54000000:
            raise ValueError("iOS 7 derived-handle rejection is not B.CC")
        uid_compare_word = 0x711F411F  # CMP W8, #0x7d0
        uid_compares = [off for off in range(derived_reject - 0x40,
                                             derived_reject, 4)
                        if read_word(kernel, off) == uid_compare_word]
        if len(uid_compares) != 1:
            raise ValueError("iOS 7 UID user-client rejection compare is not unique")
        uid_reject_branch = uid_compares[0] + 4
        if read_word(kernel, uid_reject_branch) & 0xFF00001F != 0x54000000:
            raise ValueError("iOS 7 UID rejection is not B.EQ")
    else:
        aes = find_unique(kernel, AES_HANDLE_SIG, "IOAES handle dispatch")
        aes_branch = aes + 16
        if kernel[aes + 8:aes + 16] != bytes.fromhex(
                "800100541f411f71"):
            raise ValueError("IOAES 0x7d0 comparison context mismatch")

    art_sig = IOS7_ART_FLOW_SIG if ios7 else ART_FLOW_SIG
    art = find_unique(kernel, art_sig, "AppleSEPARTStorage ART flow")
    art_branch = art + (4 if ios7 else 24)
    art_word = read_word(kernel, art_branch)
    if not is_cb(art_word):
        raise ValueError("AppleSEPARTStorage ART branch is not CBZ/CBNZ")
    art_name = b"IOReturn AppleSEPARTStorage::handle_first_connected()\0"
    name_off = find_unique(kernel, art_name, "AppleSEPARTStorage method string")
    name_va = finder.offset_to_va(name_off)
    nearby_refs = [ref for ref in finder.literal_refs(name_va)
                   if art_branch - 0x80 <= ref <= art_branch + 0x180]
    if not nearby_refs:
        raise ValueError("ART branch has no handle_first_connected string XREF")

    patches = [
        (debug_branch, kernel[debug_branch:debug_branch + 4], NOP,
         "enable kprintf path", {"xref": debug_ref, "string_offset": debug_string}),
        (debug_bit, kernel[debug_bit:debug_bit + 4], NOP,
         "ignore DB_KPRT bit", {}),
        (serial_load, kernel[serial_load:serial_load + 4], MOV_W8_3,
         "force serialmode=3", {"xref": serial_ref, "string_offset": serial_string}),
        (serial_test, kernel[serial_test:serial_test + 4], serial_store,
         "store serialmode=3", {}),
    ]
    # iOS 7 keeps the data-volume keys behind the persisted ART.  Forcing the
    # NO_ART branch lets the SEP firmware answer pings, but disk0s1s2 remains
    # unreadable (HFS GetMasterBlock returns Error 83).  Preserve the native
    # ART_LOAD/ART_NO_ART decision there.  The iOS 8 ramdisk path still needs
    # the established NO_ART override.
    if not ios7:
        patches.append((
            art_branch, kernel[art_branch:art_branch + 4],
            encode_b(finder.offset_to_va(art_branch),
                     branch_target(art_word,
                                   finder.offset_to_va(art_branch))),
            "force ART_NO_ART", {"method_xrefs": nearby_refs}))
    else:
        patches.extend([
            (uid_reject_branch,
             kernel[uid_reject_branch:uid_reject_branch + 4], NOP,
             "allow iOS 7 UID diagnostics through the descriptor wrapper",
             {}),
            (derived_reject_branch,
             kernel[derived_reject_branch:derived_reject_branch + 4], NOP,
             "allow iOS 7 derived-key diagnostics through the descriptor wrapper",
             {}),
        ])
        patches.append((
            secure_root_trust,
            kernel[secure_root_trust:secure_root_trust + 4], MOV_W8_1,
            "trust the restore ramdisk root for SecureRoot key derivation",
            {"method_xrefs": name_refs}))
    if aes_branch is not None:
        patches.insert(-1, (
            aes_branch, kernel[aes_branch:aes_branch + 4], NOP,
            "use UID AES path for handle 0x7d0", {}))
    return finder, patches


def patch(src, dst, profile=None, manifest=None, macho_output=False):
    src, dst = Path(src), Path(dst)
    kind, info, original, tail = extract_source(src.read_bytes())
    finder, patches = locate(original)
    kernel = bytearray(original)
    records = []
    for off, before, after, note, extra in patches:
        patch_bytes(kernel, off, before.hex(), after.hex(), note)
        records.append({"va": finder.offset_to_va(off), "file_offset": off,
                        "before": before.hex(), "after": after.hex(),
                        "note": note, "locator": "arm64-pattern+xref", **extra})
    dst.parent.mkdir(parents=True, exist_ok=True)
    if macho_output or kind == "macho":
        dst.write_bytes(kernel)
        fmt = "macho"
    else:
        dst.write_bytes(pack(bytes(kernel), info["platform"]) + tail)
        fmt = "complzss-with-monitor"
    if manifest:
        family = ("Darwin 14 / iOS 7.1" if b"root:xnu-2423." in original
                  else "Darwin 14 / iOS 8")
        write_manifest(manifest, src, dst, records,
                       {"kernel_family": family,
                        "output_format": fmt,
                        "preserved_tail_bytes": len(tail)})
    return dst


def main():
    ap = argparse.ArgumentParser(description="Pattern-patch an iOS 7/8 arm64 kernelcache")
    ap.add_argument("source"); ap.add_argument("output")
    ap.add_argument("--profile", help=argparse.SUPPRESS)
    ap.add_argument("--manifest"); ap.add_argument("--macho", action="store_true")
    a = ap.parse_args(); patch(a.source, a.output, a.profile, a.manifest, a.macho)


if __name__ == "__main__":
    main()
