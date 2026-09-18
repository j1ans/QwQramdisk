#!/usr/bin/env python3
import argparse
from pathlib import Path

from .common import patch_bytes, write_manifest
from .offsetfinder import NOP, find_unique, read_word


PRIVATE_VAR = b"/private/var"
MNT2_VAR = b"/mnt2//././."
# AppleKeyStoreKeyBagGetSystem is followed by a comparison against
# kIOReturnNotReady.  In a restore ramdisk, SecureRoot has already installed
# its own system handle, so the stock B.NE skips loading the data-volume bag.
# The MOV/MOVK/CMP sequence is independent of the BL displacement before it.
GET_SYSTEM_RESULT_SIG = bytes.fromhex("e8ffa312085e80721f00086b")


def patch(src, dst, manifest=None):
    src, dst = Path(src), Path(dst)
    raw = bytearray(src.read_bytes())
    records = []

    offsets = []
    start = 0
    while True:
        off = raw.find(PRIVATE_VAR, start)
        if off < 0:
            break
        offsets.append(off)
        raw[off:off + len(PRIVATE_VAR)] = MNT2_VAR
        records.append({"offset": off, "before": PRIVATE_VAR.hex(),
                        "after": MNT2_VAR.hex(),
                        "note": "redirect keybag storage to /mnt2",
                        "locator": "exact string"})
        start = off + len(MNT2_VAR)
    if not offsets:
        raise ValueError("keybagd has no /private/var paths")

    compare = find_unique(bytes(raw), GET_SYSTEM_RESULT_SIG,
                          "KeyBagGetSystem result comparison")
    branch = compare + len(GET_SYSTEM_RESULT_SIG)
    word = read_word(raw, branch)
    if word & 0xFF00001F != 0x54000001:
        raise ValueError("expected B.NE after KeyBagGetSystem comparison")
    before = raw[branch:branch + 4].hex()
    patch_bytes(raw, branch, before, NOP.hex(),
                "force loading the data-volume system keybag")
    records.append({"offset": branch, "before": before,
                    "after": NOP.hex(),
                    "note": "force loading the data-volume system keybag",
                    "locator": "arm64 pattern"})

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(raw)
    if manifest:
        write_manifest(manifest, src, dst, records,
                       {"relocated_path_count": len(offsets)})
    return dst


def main():
    ap = argparse.ArgumentParser(
        description="Patch iOS 7 keybagd for an SSH ramdisk /mnt2 mount")
    ap.add_argument("source")
    ap.add_argument("output")
    ap.add_argument("--manifest")
    args = ap.parse_args()
    patch(args.source, args.output, args.manifest)


if __name__ == "__main__":
    main()
