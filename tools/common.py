#!/usr/bin/env python3
import hashlib
import json
import os
import plistlib
import subprocess
from pathlib import Path


SUPPORTED_HOSTS = {
    ("Darwin", "x86_64"): ("macos", "x86_64"),
    ("Darwin", "arm64"): ("macos", "arm64"),
    ("Linux", "x86_64"): ("linux", "x86_64"),
    ("Linux", "amd64"): ("linux", "x86_64"),
    ("Linux", "aarch64"): ("linux", "arm64"),
    ("Linux", "arm64"): ("linux", "arm64"),
}


def host_platform(system=None, machine=None):
    """Return the bundled-runtime directory for a supported host."""
    if system is None or machine is None:
        uname = os.uname()
        system = uname.sysname if system is None else system
        machine = uname.machine if machine is None else machine
    try:
        return SUPPORTED_HOSTS[(system, machine)]
    except KeyError as exc:
        raise RuntimeError(
            f"unsupported host platform: {system}/{machine}; supported hosts "
            "are macOS and Linux on x86_64 or arm64") from exc


def sha256(data):
    if isinstance(data, Path):
        data = data.read_bytes()
    return hashlib.sha256(data).hexdigest()


def require_sha(data, expected, label):
    got = sha256(data)
    if got != expected:
        raise ValueError(f"{label}: unsupported input SHA-256 {got}; expected {expected}")


def patch_bytes(buf, offset, before_hex, after_hex, label):
    before = bytes.fromhex(before_hex)
    after = bytes.fromhex(after_hex)
    if len(before) != len(after):
        raise ValueError(f"{label}: patch changes length")
    got = bytes(buf[offset:offset + len(before)])
    if got != before:
        raise ValueError(
            f"{label}: unexpected bytes at 0x{offset:x}: {got.hex()} != {before_hex}")
    buf[offset:offset + len(after)] = after


def write_manifest(path, source, output, patches, extra=None):
    doc = {
        "source": str(source),
        "source_sha256": sha256(Path(source)),
        "output": str(output),
        "output_sha256": sha256(Path(output)),
        "patches": patches,
    }
    if extra:
        doc.update(extra)
    Path(path).write_text(json.dumps(doc, indent=2) + "\n")


def run(args, cwd=None, capture=False):
    args = [str(x) for x in args]
    if capture:
        return subprocess.run(args, cwd=cwd, check=True, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    subprocess.run(args, cwd=cwd, check=True)


def kit_bin(tools_root, name):
    """Resolve a bundled host tool (the old function name is API-compatible)."""
    root = Path(tools_root).expanduser().resolve()
    platform_name, arch = host_platform()
    candidates = [root / "bin" / platform_name / arch / name]
    if platform_name == "macos":
        candidates.append(root / "bin/macos" / name)
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    raise FileNotFoundError(
        f"cannot find executable bundled tool {name} for "
        f"{platform_name}/{arch} under {root}/bin")


def select_identity(build_manifest, device, board):
    doc = plistlib.loads(Path(build_manifest).read_bytes())
    for identity in doc["BuildIdentities"]:
        info = identity.get("Info", {})
        variant = str(info.get("Variant", ""))
        devclass = str(info.get("DeviceClass", ""))
        if devclass.lower() == board.lower() and "Erase" in variant:
            return identity
    for identity in doc["BuildIdentities"]:
        if str(identity.get("Info", {}).get("DeviceClass", "")).lower() == board.lower():
            return identity
    raise ValueError(f"BuildManifest has no identity for {device}/{board}")


def manifest_path(identity, component):
    try:
        return identity["Manifest"][component]["Info"]["Path"]
    except KeyError as exc:
        raise ValueError(f"BuildManifest lacks {component}") from exc
