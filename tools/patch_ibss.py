#!/usr/bin/env python3
import argparse
from pathlib import Path
from .common import patch_bytes, write_manifest
from .offsetfinder import (MOV_X0_0_RET, NOP, RawArm64, adr_target,
                           find_unique, read_word, validate_iboot)


IMG4_DECODER_SIG = bytes.fromhex("e8071f32e00000b4c10000b4")
IOS7_RSA_ANCHOR = bytes.fromhex(
    "cb49a8520b6988721f010b6b00050054e949a85289488a72")
IOS7_RSA_PROLOGUE = bytes.fromhex(
    "fd7bbfa9fd030091f44fbfa9f657bfa9ff0301d1f30301aa")
UID_MASK_SIG = bytes.fromhex("7f020071090080128812891a1f000071a112891ae00308aa")
IOS7_UID_MASK_SIG = bytes.fromhex(
    "090080127f020031c812891a1f0000318112891ae00308aa")
UID_DISABLE_SIG = bytes.fromhex("680640b9a80098370100801200008052")


def locate(raw):
    version = validate_iboot(raw)
    finder = RawArm64(raw)
    if version.startswith("iBoot-1940."):
        # iPatcher's proven iOS 7 method anchors on the unique IMG4 property
        # dispatcher case for BNCH, then replaces the enclosing function's
        # real stack-frame prologue.  The superficially similar F7 error block
        # used by newer patchfinders is inside a function on 1940.x and must
        # never be changed to RET.
        rsa_anchor = find_unique(raw, IOS7_RSA_ANCHOR,
                                 "iOS 7 RSA dispatcher anchor")
        sigcheck = rsa_anchor - 0x2C0
        if raw[sigcheck:sigcheck + len(IOS7_RSA_PROLOGUE)] != IOS7_RSA_PROLOGUE:
            raise ValueError("iOS 7 RSA function prologue mismatch")
        disable = find_unique(raw, UID_DISABLE_SIG,
                              "early UID-disable sequence") + 16
        uid = find_unique(raw, IOS7_UID_MASK_SIG,
                          "iOS 7 bootx UID-mask decision") + 16
        return version, [
            (sigcheck, raw[sigcheck:sigcheck + 8].hex(),
             MOV_X0_0_RET.hex(), "Image4 signature check return 0",
             {"xref": rsa_anchor}),
            (uid, "8112891a", "e103142a",
             "preserve iOS 7 bootx UID mask", {}),
            (disable, raw[disable:disable + 4].hex(), NOP.hex(),
             "skip early UID-disable call", {}),
        ]
    decoder = find_unique(raw, IMG4_DECODER_SIG, "Image4 manifest decoder")
    call = finder.find_call_ref(decoder, "Image4 decoder call XREF")
    callback_refs = []
    for off in range(call + 4, call + 0x40, 4):
        word = read_word(raw, off)
        target = adr_target(word, off)
        if target is not None and word & 31 == 2:
            callback_refs.append((off, target))
    if len(callback_refs) != 1:
        raise ValueError("Image4 callback ADR x2 is not unique")
    callback_ref, callback = callback_refs[0]
    if raw[callback:callback + 8] != bytes.fromhex("f85fbca9f65701a9"):
        raise ValueError("Image4 callback prologue mismatch")
    uid = find_unique(raw, UID_MASK_SIG, "UID-mask decision") + 16
    disable = find_unique(raw, UID_DISABLE_SIG, "early UID-disable sequence") + 16
    return version, [
        (callback, raw[callback:callback + 8].hex(), MOV_X0_0_RET.hex(),
         "Image4 validation callback return 0", {"xref": callback_ref}),
        (uid, "a112891a", "e103152a", "preserve target UID mask", {}),
        (disable, raw[disable:disable + 4].hex(), NOP.hex(),
         "skip early UID-disable call", {}),
    ]


def patch(src, dst, profile=None, manifest=None):
    src, dst = Path(src), Path(dst)
    raw = bytearray(src.read_bytes())
    version, patches = locate(bytes(raw))
    records = []
    for off, before, after, note, extra in patches:
        patch_bytes(raw, off, before, after, note)
        records.append({"offset": off, "before": before, "after": after,
                        "note": note, "locator": "arm64-pattern+xref", **extra})
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(raw)
    if manifest:
        write_manifest(manifest, src, dst, records, {"iboot_version": version})
    return dst


def main():
    ap = argparse.ArgumentParser(description="Pattern-patch decrypted iOS 7/8 arm64 iBSS")
    ap.add_argument("source"); ap.add_argument("output")
    ap.add_argument("--profile", help=argparse.SUPPRESS)
    ap.add_argument("--manifest")
    a = ap.parse_args(); patch(a.source, a.output, a.profile, a.manifest)


if __name__ == "__main__":
    main()
