#!/usr/bin/env python3
"""Run the iOS 7/8 pattern regression against locally fetched samples."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.patch_ibec import locate as locate_ibec
from tools.patch_ibss import locate as locate_ibss
from tools.patch_kernel import locate as locate_kernel


EXPECTED = {
    "11B651": {"ibss": [0xC0E8, 0xCCB0, 0x1222C],
                "ibec": [0x12B7C, 0x13620, 0x13714, 0x13934, 0x1851C,
                         0x1D778, 0x321E8, 0x1505C, 0x15060, 0x15070],
                "kernel": [0x1AA30, 0x1AA38, 0x1AA80, 0x1AA84,
                           0x68C7FC, 0x68C830, 0x595FF0]},
    "11D167": {"ibss": [0xC0DC, 0xCCA4, 0x12418],
                "ibec": [0x12B9C, 0x13640, 0x13734, 0x13954, 0x18540,
                         0x1D778, 0x321B8, 0x1507C, 0x15080, 0x15090],
                "kernel": [0x1ACC0, 0x1ACC8, 0x1AD10, 0x1AD14,
                           0x699824, 0x699858, 0x59F1BC]},
    "11D201": {"ibss": [0xC0DC, 0xCCA4, 0x12418],
                "ibec": [0x12B9C, 0x13640, 0x13734, 0x13954, 0x18540,
                         0x1D778, 0x321B8, 0x1507C, 0x15080, 0x15090],
                "kernel": [0x1ACC0, 0x1ACC8, 0x1AD10, 0x1AD14,
                           0x698824, 0x698858, 0x59E1BC]},
    "11D257": {"ibss": [0xC0DC, 0xCCA4, 0x12418],
                "ibec": [0x12B9C, 0x13640, 0x13734, 0x13954, 0x18540,
                         0x1D778, 0x321B8, 0x1507C, 0x15080, 0x15090],
                "kernel": [0x1ACC0, 0x1ACC8, 0x1AD10, 0x1AD14,
                           0x699824, 0x699858, 0x59F1BC]},
    "12A365": {"ibss": [0xB2E0, 0xBFF4, 0x1144C],
                "ibec": [0x12D8C, 0x121F0, 0x12238, 0x132F4, 0x17E14,
                         0x133E8, 0x1C9C4, 0x34298, 0x14BB4],
                "kernel": [0xCA7CC, 0xCA7D4, 0xCA81C, 0xCA820, 0x76CA54, 0xC2259C]},
    "12B411": {"ibss": [0xB2E0, 0xBFF4, 0x1144C],
                "ibec": [0x12D94, 0x121F8, 0x12240, 0x132FC, 0x17E9C,
                         0x133F0, 0x1C9C4, 0x34298, 0x14BBC],
                "kernel": [0xCA80C, 0xCA814, 0xCA85C, 0xCA860, 0x76E6A0, 0xC2659C]},
    "12D508": {"ibss": [0xB3F4, 0xC108, 0x1146C],
                "ibec": [0x12FBC, 0x12378, 0x123C0, 0x13524, 0x180C4,
                         0x13618, 0x1C9E4, 0x34350, 0x14DE4],
                "kernel": [0xCD6FC, 0xCD704, 0xCD74C, 0xCD750, 0x7746A0, 0xC2E59C]},
    "12F70": {"ibss": [0xB430, 0xC144, 0x1146C],
               "ibec": [0x13040, 0x123FC, 0x12444, 0x135A8, 0x18070,
                        0x1369C, 0x1C9E4, 0x342B0, 0x14E68],
               "kernel": [0xD0C84, 0xD0C8C, 0xD0CD4, 0xD0CD8, 0x78E6A0, 0xC5253C]},
    "12H321": {"ibss": [0xB464, 0xC178, 0x1146C],
                "ibec": [0x130EC, 0x124C8, 0x12524, 0x13654, 0x1811C,
                         0x13748, 0x1C9E4, 0x34EC0, 0x14F14],
                "kernel": [0xD107C, 0xD1084, 0xD10CC, 0xD10D0, 0x7966A0, 0xC6D53C]},
}


def offsets(patches):
    return [item[0] for item in patches]


def decrypted_dir(sample_root, build):
    candidates = [
        sample_root / build / "decrypted",
        sample_root / f"n53-{build}" / "decrypted",
        ROOT / "cache" / f"n53-{build}" / "decrypted",
    ]
    for candidate in candidates:
        if ((candidate / "iBSS.raw").is_file()
                and (candidate / "iBEC.raw").is_file()
                and any((candidate / name).is_file()
                        for name in ("kernel.macho", "Kernelcache.macho"))):
            return candidate
    tried = "\n".join(f"  {path}" for path in candidates)
    raise FileNotFoundError(f"{build}: decrypted sample set is incomplete; tried:\n{tried}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sample_root", type=Path,
                    help="directory containing BUILD/decrypted/{iBSS.raw,iBEC.raw,kernel.macho}")
    args = ap.parse_args()
    for build, expected in EXPECTED.items():
        dec = decrypted_dir(args.sample_root, build)
        _, ibss = locate_ibss((dec / "iBSS.raw").read_bytes())
        _, ibec = locate_ibec((dec / "iBEC.raw").read_bytes())
        kernel_path = dec / "kernel.macho"
        if not kernel_path.is_file():
            kernel_path = dec / "Kernelcache.macho"
        _, kernel = locate_kernel(kernel_path.read_bytes())
        got = {"ibss": offsets(ibss), "ibec": offsets(ibec),
               "kernel": offsets(kernel)}
        if got != expected:
            raise SystemExit(f"{build}: mismatch\nexpected={expected}\ngot={got}")
        print(f"{build}: PASS ({len(ibss)} iBSS, {len(ibec)} iBEC, {len(kernel)} kernel patches)")


if __name__ == "__main__":
    main()
