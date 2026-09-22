"""Dump activation records from a booted ramdisk over SSH.

The result is layout compatible with Legacy-iOS-Kit's
device_dumpactivation staging tree so the tar can be dropped into
Legacy-iOS-Kit's saved/<device>/ directory for IPSW stitching:

    private/var/root/Library/Lockdown/**                          root:wheel
    private/var/mobile/Media/iTunes_Control/iTunes/IC-Info.sidv  mobile 501:501
    private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv
    private/var/wireless/Library/Preferences/com.apple.commcenter.plist
                                                                  wireless 25:25

The iRam userland shipped in the ramdisk (tar, ls -l) is linked against
iOS 9+ libSystem symbols and crashes on the iOS 7 restore ramdisk
(_fdopendir/_clock_gettime lazy binding failures), so nothing is archived
on the device.  find -ls, cat, and scp work on every tested ramdisk; the
files are pulled over scp and the tar is built on the host.

iOS 7 keeps its activation records in /mnt2/root/Library/Lockdown while
iOS 8 uses /mnt2/mobile/Library/mad (both are normalized into
private/var/root/Library/Lockdown like Legacy-iOS-Kit does).  The source
suggested by the installed version is preferred, with the other location
as a fallback whenever it is the one holding a *_record.plist.
"""
import io
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from .boot import ssh_command
from .common import kit_bin

LOCKDOWN_REMOTE = "/mnt2/root/Library/Lockdown"
MAD_REMOTE = "/mnt2/mobile/Library/mad"
SYSTEM_VERSION_REMOTE = "/mnt1/System/Library/CoreServices/SystemVersion.plist"
# Legacy-iOS-Kit actrec_files: copied next to the records in every dump.
SUPPLEMENTARY = {
    "/mnt2/mobile/Media/iTunes_Control/iTunes/IC-Info.sidv":
        "private/var/mobile/Media/iTunes_Control/iTunes/IC-Info.sidv",
    "/mnt2/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv":
        "private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv",
    "/mnt2/wireless/Library/Preferences/com.apple.commcenter.plist":
        "private/var/wireless/Library/Preferences/com.apple.commcenter.plist",
}
TAR_ROOT = "private/var/root/Library/Lockdown"
# mkdir -p + chown -R semantics from device_dumpactivation.
SYNTHETIC_DIRS = [
    ("private", 0, 0), ("private/var", 0, 0),
    ("private/var/root", 0, 0), ("private/var/root/Library", 0, 0),
    ("private/var/mobile", 501, 501),
    ("private/var/mobile/Media", 501, 501),
    ("private/var/mobile/Media/iTunes_Control", 501, 501),
    ("private/var/mobile/Media/iTunes_Control/iTunes", 501, 501),
    ("private/var/mobile/Library", 501, 501),
    ("private/var/mobile/Library/FairPlay", 501, 501),
    ("private/var/mobile/Library/FairPlay/iTunes_Control", 501, 501),
    ("private/var/mobile/Library/FairPlay/iTunes_Control/iTunes", 501, 501),
    ("private/var/wireless", 25, 25),
    ("private/var/wireless/Library", 25, 25),
    ("private/var/wireless/Library/Preferences", 25, 25),
]
UNAMES = {0: "root", 501: "mobile", 25: "wireless"}
GNAMES = {0: "wheel", 501: "mobile", 25: "wireless"}


def _ssh_base(kit_root, port):
    return [str(kit_bin(kit_root, "sshpass")), "-p", "alpine", "ssh", "-p", str(port),
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10", "root@localhost"]


def ssh_run(kit_root, port, remote):
    result = subprocess.run(_ssh_base(kit_root, port) + [remote],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError("remote command failed: " + remote.strip().splitlines()[0]
                           + (f": {detail}" if detail else ""))
    return result.stdout.decode(errors="replace")


def scp_pull(kit_root, port, remote, dest_dir, recursive=True):
    """Copy root@localhost:<remote> into dest_dir through the bundled sshpass."""
    command = [str(kit_bin(kit_root, "sshpass")), "-p", "alpine",
               "scp", "-P", str(port),
               "-o", "PreferredAuthentications=password",
               "-o", "PubkeyAuthentication=no",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    command.append("-r" if recursive else "-p")
    command += [f"root@localhost:{remote}", str(dest_dir)]
    result = None
    for attempt in (1, 2):
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        if result.returncode == 0:
            return
        if attempt == 1:
            time.sleep(2)
    raise RuntimeError(f"scp failed for {remote}: "
                       + result.stderr.decode(errors="replace").strip())


def device_version(kit_root, port):
    doc = plistlib.loads(ssh_run(kit_root, port,
                                 f"cat {SYSTEM_VERSION_REMOTE}").encode())
    return doc["ProductVersion"], doc["ProductBuildVersion"]


_FIND_LS = re.compile(
    r"\s*\d+\s+\d+\s+([drwx-]{10})\s+\d+\s+(\w+)\s+(\w+)\s+(\d+)\s+.*?\s+(/\S.*)$")
_SYMBOLIC = {"r": 4, "w": 2, "x": 1}


def list_tree(kit_root, port, remote_path):
    """Parse `find <path> -ls` into (rel, mode, uid, gid, size, is_dir) rows.

    The tree root itself is kept with rel="" so its real mode survives
    (/mnt2/root/Library/Lockdown is 0700 on device).
    """
    rows = []
    for line in ssh_run(kit_root, port, f"find {remote_path} -ls").splitlines():
        match = _FIND_LS.match(line)
        if not match:
            continue
        mode, owner, group, size, path = match.groups()
        if path != remote_path and not path.startswith(remote_path + "/"):
            continue
        bits = 0
        for chunk in (mode[1:4], mode[4:7], mode[7:10]):
            digit = 0
            for char in chunk:
                digit += _SYMBOLIC.get(char, 0)
            bits = bits * 8 + digit
        uid = int(owner) if owner.isdigit() else {"root": 0}.get(owner, 0)
        gid = int(group) if group.isdigit() else {"wheel": 0}.get(group, 0)
        rows.append((path[len(remote_path):].lstrip("/"), bits, uid, gid,
                     int(size), mode.startswith("d")))
    return rows


def _has_record(rows):
    return any(rel.endswith("_record.plist") for rel, _, _, _, _, is_dir in rows
               if not is_dir)


def _add_dir(tf, name, mode, uid, gid, mtime):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    info.uid, info.gid = uid, gid
    info.uname = UNAMES.get(uid, str(uid))
    info.gname = GNAMES.get(gid, str(gid))
    info.mtime = mtime
    tf.addfile(info)


def _add_file(tf, name, data, mode, uid, gid, mtime):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid, info.gid = uid, gid
    info.uname = UNAMES.get(uid, str(uid))
    info.gname = GNAMES.get(gid, str(gid))
    info.mtime = mtime
    tf.addfile(info, io.BytesIO(data))


def _owner_for(tar_path):
    if tar_path.startswith("private/var/mobile/"):
        return 501, 501
    if tar_path.startswith("private/var/wireless/"):
        return 25, 25
    return 0, 0


def dump_activation(kit_root, port, out=None, output_dir=None):
    """Collect activation records from the running ramdisk and build the tar.

    Returns (path, info); info carries the human-readable dump summary.
    """
    try:
        ssh_run(kit_root, port, "echo ready")
    except RuntimeError as exc:
        raise RuntimeError(
            f"cannot reach the ramdisk SSH server on port {port}; boot the "
            "ramdisk first (or check iproxy and the USB cable)") from exc
    if ssh_command(kit_root, port, "/usr/local/bin/mount-mnt2") != 0:
        raise RuntimeError("mount-mnt2 failed on the device; /mnt2 must be "
                           "mounted and readable before dumping activation records")
    version, build = device_version(kit_root, port)
    major = int(re.match(r"\d+", version).group())

    candidates = ([MAD_REMOTE, LOCKDOWN_REMOTE] if major >= 8
                  else [LOCKDOWN_REMOTE, MAD_REMOTE])
    source, rows = None, []
    for candidate in candidates:
        try:
            listing = list_tree(kit_root, port, candidate)
        except RuntimeError:
            continue  # path missing on this firmware
        if _has_record(listing):
            source, rows = candidate, listing
            break
        if source is None:
            source, rows = candidate, listing  # keep for the error message
    if not _has_record(rows):
        raise RuntimeError(
            f"no *_record.plist under {LOCKDOWN_REMOTE} or {MAD_REMOTE} "
            f"(iOS {version}-{build}); the device appears to be unactivated")

    source_dir_name = Path(source).name
    staging = Path(tempfile.mkdtemp(prefix="qwq-activation-"))
    mtime = int(time.time())
    try:
        scp_pull(kit_root, port, source, staging)
        pulled = {}
        for remote in SUPPLEMENTARY:
            if ssh_run(kit_root, port,
                       f'[ -e "{remote}" ] && echo yes || echo no').strip().endswith("yes"):
                scp_pull(kit_root, port, remote, staging, recursive=False)
                pulled[remote] = staging / Path(remote).name
            else:
                print(f"[activation] not present, skipping: {remote}",
                      file=sys.stderr, flush=True)

        members = []  # (tar_path, local_or_None, mode, uid, gid, size)
        for rel, mode, uid, gid, size, is_dir in rows:
            tar_path = f"{TAR_ROOT}/{rel}" if rel else TAR_ROOT
            if is_dir:
                members.append((tar_path, None, mode, uid, gid, 0))
                continue
            local = staging / source_dir_name / rel
            if not local.is_file() or local.stat().st_size != size:
                raise RuntimeError(f"pulled copy of {rel} does not match the "
                                   f"device listing ({size} bytes expected)")
            members.append((tar_path, local, mode, uid, gid, size))
        for remote, tar_path in SUPPLEMENTARY.items():
            if remote in pulled:
                uid, gid = _owner_for(tar_path)
                members.append((tar_path, pulled[remote], 0o644, uid, gid,
                                pulled[remote].stat().st_size))

        if out:
            target = Path(out)
        elif output_dir:
            target = Path(output_dir) / f"activation-{version}-{build}.tar"
        else:
            target = Path(f"activation-{version}-{build}.tar")
        target.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(target, "w", format=tarfile.GNU_FORMAT) as tf:
            real_dirs = {name: (mode, uid, gid) for name, local, mode, uid, gid, _
                         in members if local is None}
            for name, uid, gid in SYNTHETIC_DIRS:
                if name not in real_dirs:
                    _add_dir(tf, name, 0o755, uid, gid, mtime)
            for name in sorted(real_dirs):
                mode, uid, gid = real_dirs[name]
                _add_dir(tf, name, mode, uid, gid, mtime)
            for name, local, mode, uid, gid, size in sorted(members):
                if local is not None:
                    _add_file(tf, name, local.read_bytes(), mode, uid, gid, mtime)

        with tarfile.open(target) as tf:
            names = tf.getnames()
            records = [name for name in names if "_record.plist" in name]
            if not records:
                raise RuntimeError("verification failed: no *_record.plist in the tar")
        info = {
            "version": version, "build": build, "source": source,
            "activation_records": records,
            "record_files": sum(1 for rel, _, _, _, _, is_dir in rows if not is_dir),
            "supplementary": [Path(remote).name for remote in pulled],
            "members": len(names),
        }
        return target, info
    finally:
        shutil.rmtree(staging, ignore_errors=True)
