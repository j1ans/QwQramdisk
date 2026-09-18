#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from tools.boot import boot, ssh_command
from tools.build import build
from tools.common import kit_bin
from tools.device import profile_for_version, select_profile
from tools.fetch import fetch_components
from tools.patch_ibec import patch as patch_ibec
from tools.patch_ibss import patch as patch_ibss
from tools.patch_kernel import patch as patch_kernel
from tools.profiles import PROFILES


def default_kit():
    return str(Path.home() / "Legacy-iOS-kit")


def add_kit(ap):
    ap.add_argument("--kit", default=default_kit(), help="Legacy-iOS-Kit directory")


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
          f"({device['MODE']}), selected {profile}", file=sys.stderr)
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
    p = sub.add_parser("mount", help="run the one-command /mnt2 mount over SSH"); add_kit(p)
    p.add_argument("--port", type=int, default=2236)
    p = sub.add_parser("ssh", help="open an interactive root shell"); add_kit(p)
    p.add_argument("--port", type=int, default=2236)
    for name, help_text in [("patch-ibss", "patch a decrypted iBSS"),
                            ("patch-ibec", "patch a decrypted iBEC"),
                            ("patch-kernel", "patch a decrypted kernelcache")]:
        p = sub.add_parser(name, help=help_text); p.add_argument("source"); p.add_argument("output")
        p.add_argument("--version", default="8.3"); p.add_argument("--manifest")
    return ap


def main():
    a = parser().parse_args()
    if a.command in ("versions", "profiles"):
        for name, p in PROFILES.items():
            if name in ("n53-12F70", "n53-11D201"):
                tested = " (mnt2-rw-tested)"
            else:
                tested = ""
            print(f"iOS {p['version']:5} build {p['build']:7}{tested}")
    elif a.command == "doctor":
        for name in ("pzb", "img4", "hfsplus", "irecovery", "ipwnder",
                     "gaster", "iproxy", "sshpass"):
            print(f"{name}: {kit_bin(a.kit, name)}")
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
    elif a.command == "mount":
        raise SystemExit(ssh_command(
            a.kit, a.port, "/usr/local/bin/mount-mnt2"))
    elif a.command == "ssh":
        ssh_command(a.kit, a.port, None, True)
    elif a.command == "patch-ibss":
        patch_ibss(a.source, a.output, profile_for_version(a.version), a.manifest)
    elif a.command == "patch-ibec":
        patch_ibec(a.source, a.output, profile_for_version(a.version), a.manifest)
    elif a.command == "patch-kernel":
        patch_kernel(a.source, a.output, profile_for_version(a.version), a.manifest)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("ERROR: interrupted")
    except (RuntimeError, ValueError, FileNotFoundError,
            subprocess.CalledProcessError) as exc:
        raise SystemExit(f"ERROR: {exc}")
