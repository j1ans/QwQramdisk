#!/usr/bin/env python3
import argparse
from pathlib import Path
from .common import patch_bytes, write_manifest
from .offsetfinder import (MOV_X0_0_RET, MOV_X0_1, NOP, RawArm64,
                           adr_target, branch_target, cb_nonzero, encode_adr,
                           encode_b, find_unique, is_cb, read_word,
                           validate_iboot)


IMG4_DECODER_SIG = bytes.fromhex("e8071f32e00000b4c10000b4")
IOS7_RSA_ANCHOR = bytes.fromhex(
    "cb49a8520b6988721f010b6b00050054e949a85289488a72")
IOS7_RSA_PROLOGUE = bytes.fromhex(
    "fd7bbfa9fd030091f44fbfa9f657bfa9ff0301d1f30301aa")
DIGEST_HELPER_SIG = bytes.fromhex(
    "f44fbea9fd7b01a9fd430091ff4300d1f30302aae80300aa"
    "e2230091e3130091e00301aae10308aa")
UID_MASK_SIG = bytes.fromhex("7f020071090080128812891a1f000071a112891ae00308aa")
IOS7_UID_MASK_SIG = bytes.fromhex(
    "090080127f020031c812891a1f0000318112891ae00308aa")
UID_DISABLE_SIG = bytes.fromhex("680640b9a80098370100801200008052")
BOOTARGS = b"rd=md0 -v serial=3 amfi=0xff cs_enforcement_disable=1\0"
IOS7_BOOTARGS = (
    b"rd=md0 debug=0x2014e -v wdt=-1 nand-enable-reformat=1 -restore "
    b"amfi=0xff cs_enforcement_disable=1\0"
)


def _second_bl_after_xref(raw, finder, string):
    string_off = find_unique(raw, string + b"\0", string.decode())
    ref = finder.find_literal_ref(string_off, f"{string.decode()} XREF")
    calls = [off for off in range(ref + 4, ref + 0x40, 4)
             if read_word(raw, off) & 0xFC000000 == 0x94000000]
    if len(calls) != 2:
        raise ValueError(f"{string.decode()} call sequence is not unique: {calls}")
    return ref, calls[1]


def _locate_ios7(raw, finder, version):
    rsa_anchor = find_unique(raw, IOS7_RSA_ANCHOR,
                             "iOS 7 RSA dispatcher anchor")
    sigcheck = rsa_anchor - 0x2C0
    if raw[sigcheck:sigcheck + len(IOS7_RSA_PROLOGUE)] != IOS7_RSA_PROLOGUE:
        raise ValueError("iOS 7 RSA function prologue mismatch")

    debug_ref, debug_call = _second_bl_after_xref(
        raw, finder, b"debug-enabled")
    uid_key_ref, uid_key_call = _second_bl_after_xref(
        raw, finder, b"uid-aes-key")
    uid_key_branch = uid_key_call + 4
    if not is_cb(read_word(raw, uid_key_branch)):
        raise ValueError("uid-aes-key capability branch missing")
    system_trusted_ref, system_trusted_call = _second_bl_after_xref(
        raw, finder, b"system-trusted")
    system_trusted_branch = system_trusted_call + 4
    if not is_cb(read_word(raw, system_trusted_branch)):
        raise ValueError("system-trusted capability branch missing")
    uid = find_unique(raw, IOS7_UID_MASK_SIG,
                      "iOS 7 bootx UID-mask decision") + 16
    disable = find_unique(raw, UID_DISABLE_SIG,
                          "early UID-disable sequence") + 16

    default_args = find_unique(
        raw, b"rd=md0 nand-enable-reformat=1 -progress\0",
        "default boot-args")
    boot_ref = finder.find_literal_ref(default_args,
                                       "default boot-args XREF")
    scratch = find_unique(raw, b"Reliance on this certificate by any",
                          "boot-args scratch string")
    scratch_end = raw.find(b"\0", scratch)
    if scratch_end < 0 or len(IOS7_BOOTARGS) > scratch_end - scratch + 1:
        raise ValueError("iOS 7 boot arguments exceed certificate scratch space")
    # 1940.x loads the production and recovery strings into x8/x9 and then
    # chooses one with CSEL.  Redirect the x8 ADD into an ADR and force x20 to
    # retain x8.  Validate the complete local instruction pair before editing.
    csel = boot_ref + 16
    adrp = boot_ref - 4
    # The page delta differs between the iPhone and iPad layouts (ADRP and
    # ADRP with the sign bit set), while both instructions load x8.  Match the
    # opcode and destination register instead of pinning the encoded delta.
    if read_word(raw, adrp) & 0x9F00001F != 0x90000008:
        raise ValueError("iOS 7 boot-args ADRP context mismatch")
    if raw[csel:csel + 4] != bytes.fromhex("3401889a"):
        raise ValueError("iOS 7 boot-args CSEL context mismatch")

    return version, [
        (sigcheck, raw[sigcheck:sigcheck + 8], MOV_X0_0_RET,
         "Image4 signature check return 0", {"xref": rsa_anchor}),
        (debug_call, raw[debug_call:debug_call + 4], MOV_X0_1,
         "accept debug/recovery capability", {"xref": debug_ref}),
        (uid_key_branch, raw[uid_key_branch:uid_key_branch + 4], NOP,
         "publish uid-aes-key capability", {"xref": uid_key_ref}),
        (system_trusted_branch,
         raw[system_trusted_branch:system_trusted_branch + 4], NOP,
         "publish system-trusted for SecureRoot key derivation",
         {"xref": system_trusted_ref}),
        (uid, raw[uid:uid + 4], bytes.fromhex("e103142a"),
         "preserve iOS 7 bootx UID mask", {}),
        (disable, raw[disable:disable + 4], NOP,
         "skip early UID-disable call", {}),
        (scratch, raw[scratch:scratch + len(IOS7_BOOTARGS)],
         IOS7_BOOTARGS, "relocated iOS 7 restore boot arguments", {}),
        (adrp, raw[adrp:adrp + 4], NOP,
         "clear old boot-args ADRP", {"xref": boot_ref}),
        (boot_ref, raw[boot_ref:boot_ref + 4],
         encode_adr(boot_ref, scratch, read_word(raw, boot_ref) & 31),
         "redirect boot-args ADR", {"target": scratch}),
        (csel, raw[csel:csel + 4], bytes.fromhex("f40308aa"),
         "select relocated boot arguments", {"xref": boot_ref}),
    ]


def locate(raw):
    version = validate_iboot(raw)
    finder = RawArm64(raw)
    if version.startswith("iBoot-1940."):
        return _locate_ios7(raw, finder, version)
    decoder = find_unique(raw, IMG4_DECODER_SIG, "Image4 manifest decoder")
    decoder_call = finder.find_call_ref(decoder, "Image4 decoder call XREF")

    callback_adrs = []
    for off in range(decoder_call + 4, decoder_call + 0x40, 4):
        word = read_word(raw, off)
        if adr_target(word, off) is not None and word & 31 == 2:
            callback_adrs.append(off)
    if len(callback_adrs) != 1:
        raise ValueError("Image4 callback ADR x2 is not unique")
    callback_adr = callback_adrs[0]
    callback_call = finder.next_bl(callback_adr + 4, callback_adr + 0x20,
                                   "Image4 callback invocation")
    first_branch = callback_call + 4
    first_word = read_word(raw, first_branch)
    if not is_cb(first_word):
        raise ValueError("unexpected aggregate-manifest branch")
    if cb_nonzero(first_word):
        first_after = NOP
        success = first_branch + 4
    else:
        success = branch_target(first_word, first_branch)
        first_after = encode_b(first_branch, success)
    failure = branch_target(first_word, first_branch) if cb_nonzero(first_word) else None
    root_results = []
    for call_off in range(success, success + 0x80, 4):
        if read_word(raw, call_off) & 0xFC000000 != 0x94000000:
            continue
        for branch_off in range(call_off + 4, call_off + 16, 4):
            word = read_word(raw, branch_off)
            if (is_cb(word) and cb_nonzero(word)
                    and (failure is None or branch_target(word, branch_off) == failure)):
                root_results.append((call_off, branch_off))
    if len(root_results) != 1:
        raise ValueError(f"root-manifest hash result is not unique: {root_results}")
    root_call, root_branch = root_results[0]
    root_word = read_word(raw, root_branch)
    if not is_cb(root_word) or not cb_nonzero(root_word):
        raise ValueError("unexpected root-manifest result branch")

    digest = find_unique(raw, DIGEST_HELPER_SIG, "payload digest helper")
    debug_ref, debug_call = _second_bl_after_xref(raw, finder, b"debug-enabled")
    uid_key_ref, uid_key_call = _second_bl_after_xref(raw, finder, b"uid-aes-key")
    uid_key_branch = uid_key_call + 4
    if not is_cb(read_word(raw, uid_key_branch)):
        raise ValueError("uid-aes-key capability branch missing")
    uid = find_unique(raw, UID_MASK_SIG, "UID-mask decision") + 16
    disable = find_unique(raw, UID_DISABLE_SIG, "early UID-disable sequence") + 16

    default_args = find_unique(raw, b"rd=md0 nand-enable-reformat=1 -progress\0",
                               "default boot-args")
    boot_ref = finder.find_adr_ref(default_args, "default boot-args XREF")
    scratch = find_unique(raw, b"Reliance on this certificate by any",
                          "boot-args scratch string")
    if len(BOOTARGS) > 0x55:
        raise ValueError("boot arguments exceed scratch space")

    patches = [
        (digest, raw[digest:digest + 8], MOV_X0_0_RET,
         "bypass payload digest compare", {}),
        (first_branch, raw[first_branch:first_branch + 4], first_after,
         "force aggregate manifest success", {"xref": decoder_call}),
        (root_branch, raw[root_branch:root_branch + 4], NOP,
         "ignore stale root-manifest hash", {}),
        (debug_call, raw[debug_call:debug_call + 4], MOV_X0_1,
         "accept debug/recovery capability", {"xref": debug_ref}),
        (uid, bytes.fromhex("a112891a"), bytes.fromhex("e103152a"),
         "preserve bootx UID mask", {}),
        (uid_key_branch, raw[uid_key_branch:uid_key_branch + 4], NOP,
         "publish uid-aes-key capability", {"xref": uid_key_ref}),
        (disable, raw[disable:disable + 4], NOP,
         "skip early UID-disable call", {}),
        (scratch, raw[scratch:scratch + 0x55], BOOTARGS.ljust(0x55, b"\0"),
         "relocated boot arguments", {}),
        (boot_ref, raw[boot_ref:boot_ref + 4],
         encode_adr(boot_ref, scratch, read_word(raw, boot_ref) & 31),
         "redirect boot-args ADR", {"target": scratch}),
    ]
    return version, patches


def patch(src, dst, profile=None, manifest=None):
    src, dst = Path(src), Path(dst)
    raw = bytearray(src.read_bytes())
    version, patches = locate(bytes(raw))
    records = []
    for off, before, after, note, extra in patches:
        patch_bytes(raw, off, before.hex(), after.hex(), note)
        records.append({"offset": off, "before": before.hex(), "after": after.hex(),
                        "note": note, "locator": "arm64-pattern+xref", **extra})
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(raw)
    if manifest:
        write_manifest(manifest, src, dst, records, {"iboot_version": version})
    return dst


def main():
    ap = argparse.ArgumentParser(description="Pattern-patch decrypted iOS 7/8 arm64 iBEC")
    ap.add_argument("source"); ap.add_argument("output")
    ap.add_argument("--profile", help=argparse.SUPPRESS)
    ap.add_argument("--manifest")
    a = ap.parse_args(); patch(a.source, a.output, a.profile, a.manifest)


if __name__ == "__main__":
    main()
