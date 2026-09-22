#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from tools.activation import dump_activation
from tools.boot import boot, ssh_command
from tools.build import build
from tools.common import kit_bin
from tools.device import select_profile
from tools.fetch import fetch_components
from tools.patch_ibec import patch as patch_ibec
from tools.patch_ibss import patch as patch_ibss
from tools.patch_kernel import patch as patch_kernel
from tools.profiles import PROFILES, validation_status


def default_kit():
    return str(ROOT / "vendor")


def add_kit(ap):
    ap.add_argument(
        "--kit", default=default_kit(), metavar="TOOLS_ROOT",
        help="bundled tools root (default: repository vendor directory)")


def add_version(ap):
    add_kit(ap)
    ap.add_argument("version", nargs="?", help="installed iOS version, for example 8.3")
    ap.add_argument("--profile", help=argparse.SUPPRESS)


def resolve_profile(a, require_dfu=False):
    if getattr(a, "profile", None):
        return a.profile
    if not getattr(a, "version", None):
        raise ValueError("iOS version is required, for example: create 8.3")
    profile, device = select_profile(a.kit, a.version, require_dfu)
    print(f"Detected {device['NAME']}: {device['PRODUCT']}/{device['MODEL']} "
          f"({device['MODE']}), selected {profile} "
          f"[{validation_status(profile)}]", file=sys.stderr)
    return profile


def parser():
    ap = argparse.ArgumentParser(prog="qwqramdisk",
        description="Build and boot an iOS 7/8 arm64 /mnt2 SSH ramdisk")
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("doctor", help="check required Legacy-iOS-Kit binaries"); add_kit(p)
    sub.add_parser("versions", aliases=["profiles"], help="list supported iOS versions")
    p = sub.add_parser("fetch", help="fetch boot components for the connected device"); add_version(p)
    p.add_argument("--cache")
    p = sub.add_parser("create", help="build for the connected device and iOS version"); add_version(p)
    p.add_argument("--cache"); p.add_argument("--output")
    p.add_argument("--offline", action="store_true", help="reuse a complete cache")
    p = sub.add_parser("boot", help="boot the connected DFU device"); add_version(p)
    p.add_argument("--output"); p.add_argument("--port", type=int, default=2236)
    p.add_argument("--usb-delay", type=int, default=4,
                   help="seconds between USB send/command stages (default: 4)")
    p.add_argument("--retries", type=int, default=5,
                   help="irecovery attempts per send/command (default: 5)")
    p.add_argument("--dump-activation", nargs="?", const="", metavar="TAR",
                   help="after boot, dump activation records into a "
                        "Legacy-iOS-Kit compatible tar (default: "
                        "output/<profile>/activation-<version>-<build>.tar)")
    p = sub.add_parser("mount", help="run the one-command /mnt2 mount over SSH"); add_kit(p)
    p.add_argument("--port", type=int, default=2236)
    p = sub.add_parser("dump-activation",
                       help="dump activation records from an already-booted ramdisk")
    add_kit(p)
    p.add_argument("--port", type=int, default=2236)
    p.add_argument("--out", help="output tar path (default: ./activation-<version>-<build>.tar)")
    p = sub.add_parser("ssh", help="open an interactive root shell"); add_kit(p)
    p.add_argument("--port", type=int, default=2236)
    for name, help_text in [("patch-ibss", "patch a decrypted iBSS"),
                            ("patch-ibec", "patch a decrypted iBEC"),
                            ("patch-kernel", "patch a decrypted kernelcache")]:
        p = sub.add_parser(name, help=help_text); p.add_argument("source"); p.add_argument("output")
        p.add_argument("--version", default="8.3"); p.add_argument("--manifest")
    return ap


def _print_activation(path, info):
    print(f"Activation records: {len(info['activation_records'])} "
          f"({', '.join(info['activation_records'])})")
    print(f"Collected {info['record_files']} files from {info['source']} "
          f"(iOS {info['version']}-{info['build']}) "
          f"+ {len(info['supplementary'])} supplementary "
          f"({', '.join(info['supplementary'])})")
    print(f"Saved: {path}")


def main():
    a = parser().parse_args()
    if a.command in ("versions", "profiles"):
        print("AUTO      any     iOS 7/8 experimental A7/A8/A8X auto-detection; "
              "device-untested-use-at-own-risk")
        def version_key(item):
            name, p = item
            return (p["device"], tuple(int(x) for x in p["version"].split(".")),
                    p["build"], name)
        for name, p in sorted(PROFILES.items(), key=version_key):
            print(f"{p['device']:9} {p['board']:5} iOS {p['version']:5} "
                  f"build {p['build']:7} {validation_status(name)}")
    elif a.command == "doctor":
        for name in ("pzb", "img4", "hfsplus", "irecovery", "ipwnder",
                     "gaster", "iproxy", "sshpass"):
            print(f"{name}: {kit_bin(a.kit, name)}")
        for name in ("IM4M7", "IM4M8", "sbplist.tar"):
            path = Path(a.kit) / "resources/sshrd" / name
            if not path.is_file():
                raise FileNotFoundError(path)
            print(f"{name}: {path}")
        iram = Path(a.kit) / "resources/iram.tar"
        if not iram.is_file():
            raise FileNotFoundError(iram)
        print(f"iram.tar: {iram}")
    elif a.command == "fetch":
        profile = resolve_profile(a)
        cache = a.cache or f"cache/{profile}"
        fw, keys, files = fetch_components(a.kit, cache, profile)
        print(json.dumps({"firmware": fw, "files": {k: str(v) for k, v in files.items()}}, indent=2))
    elif a.command == "create":
        profile = resolve_profile(a, require_dfu=True)
        cache = a.cache or f"cache/{profile}"
        output = a.output or f"output/{profile}"
        doc = build(a.kit, output, cache, ROOT, profile, a.offline)
        print(json.dumps(doc, indent=2))
    elif a.command == "boot":
        profile = resolve_profile(a, require_dfu=True)
        output = a.output or f"output/{profile}"
        if a.usb_delay < 1 or a.retries < 1:
            raise ValueError("--usb-delay and --retries must be positive")
        if not boot(a.kit, output, a.port, usb_delay=a.usb_delay,
                    retries=a.retries):
            raise SystemExit("ramdisk booted but SSH did not become ready; inspect serial and iproxy.log")
        print(f"SSH ready: ./qwqramdisk ssh --port {a.port}")
        print(f"Mount /mnt2: ./qwqramdisk mount --port {a.port}")
        print(f"Dump activation records: ./qwqramdisk dump-activation --port {a.port}")
        if a.dump_activation is not None:
            path, info = dump_activation(a.kit, a.port,
                                         out=a.dump_activation or None,
                                         output_dir=output)
            _print_activation(path, info)
    elif a.command == "mount":
        raise SystemExit(ssh_command(
            a.kit, a.port, "/usr/local/bin/mount-mnt2"))
    elif a.command == "dump-activation":
        path, info = dump_activation(a.kit, a.port, out=a.out)
        _print_activation(path, info)
    elif a.command == "ssh":
        ssh_command(a.kit, a.port, None, True)
    elif a.command == "patch-ibss":
        patch_ibss(a.source, a.output, a.version, a.manifest)
    elif a.command == "patch-ibec":
        patch_ibec(a.source, a.output, a.version, a.manifest)
    elif a.command == "patch-kernel":
        patch_kernel(a.source, a.output, a.version, a.manifest)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("ERROR: interrupted")
    except (RuntimeError, ValueError, FileNotFoundError,
            subprocess.CalledProcessError) as exc:
        raise SystemExit(f"ERROR: {exc}")
