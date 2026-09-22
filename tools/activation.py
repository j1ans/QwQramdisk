"""Dump and restore the activation Lockdown folder over SSH.

The tar is simply the Lockdown folder itself:

    Lockdown/                                        (0700 root:wheel)
    Lockdown/activation_records/activation_record.plist
    Lockdown/data_ark.plist
    Lockdown/device_private_key.pem, device_public_key.pem
    Lockdown/escrow_records/**, Lockdown/pair_records/**

`dump-activation` reads /mnt2/root/Library/Lockdown (iOS 7) or
/mnt2/mobile/Library/mad (iOS 8, normalized to the Lockdown name) and
`restore-activation` writes the folder back to /mnt2/root/Library/Lockdown,
replacing the live one after taking an on-device *.bak-<timestamp> copy.

The iRam userland shipped in the ramdisk (tar, ls -l) is linked against
iOS 9+ libSystem symbols and crashes on the iOS 7 restore ramdisk
(_fdopendir/_clock_gettime lazy binding failures), so nothing is archived
on the device.  find -ls provides the listing, scp pulls files off the
device for dumps, sftp (with directories pre-created through ssh, because
dropbear's sftp-server rejects the realpath of recursive uploads) pushes
files back for restores, and the tar is assembled and verified on the host.
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
TAR_ROOT = "Lockdown"
UNAMES = {0: "root", 501: "mobile", 25: "wireless"}
GNAMES = {0: "wheel", 501: "mobile", 25: "wireless"}


def _ssh_base(kit_root, port):
    return [str(kit_bin(kit_root, "sshpass")), "-p", "alpine", "ssh", "-p", str(port),
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10", "root@localhost"]


def ssh_run(kit_root, port, remote):
    """Run one command; dropbear transiently refuses rapid successive
    authentications, so a Permission denied answer is retried briefly."""
    for attempt in (1, 2, 3):
        result = subprocess.run(_ssh_base(kit_root, port) + [remote],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return result.stdout.decode(errors="replace")
        stderr = result.stderr.decode(errors="replace")
        if "Permission denied" in stderr and attempt < 3:
            time.sleep(2)
            continue
        raise RuntimeError("remote command failed: " + remote.strip().splitlines()[0]
                           + (f": {stderr.strip()}" if stderr.strip() else ""))
    raise RuntimeError("remote command failed after retries: "
                       + remote.strip().splitlines()[0])


def _scp_args(kit_root, port):
    return [str(kit_bin(kit_root, "sshpass")), "-p", "alpine",
            "scp", "-P", str(port),
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]


def scp_pull(kit_root, port, remote, dest_dir, recursive=True):
    """Copy root@localhost:<remote> into dest_dir through the bundled sshpass."""
    command = _scp_args(kit_root, port)
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


def sftp_push_tree(kit_root, port, local_root, remote_root, dir_rels, file_rels):
    """Upload a file tree to remote_root through one sftp session.

    dropbear's sftp-server answers the realpath that `scp -r` and `put -r`
    issue for a not-yet-existing destination with a hard error, so recursive
    uploads fail.  Every directory is therefore created through ssh first
    and each file is put with an explicit existing destination path.
    """
    mkdirs = ["set -e", f'mkdir -p "{remote_root}"']
    for rel in sorted(dir_rels):
        mkdirs.append(f'mkdir -p "{remote_root}/{rel}"' if rel else "true")
    ssh_run(kit_root, port, "\n".join(mkdirs))
    with tempfile.NamedTemporaryFile("w", suffix=".sftp", delete=False) as batch:
        for rel in file_rels:
            batch.write(f'put "{Path(local_root) / rel}" "{remote_root}/{rel}"\n')
        batch_path = batch.name
    # -b must follow the -o options: parsed before -oBatchMode=no it disables
    # password authentication and sshpass has nothing to answer.
    command = [str(kit_bin(kit_root, "sshpass")), "-p", "alpine",
               "sftp", "-P", str(port),
               "-o", "BatchMode=no",
               "-o", "PreferredAuthentications=password",
               "-o", "PubkeyAuthentication=no",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-b", batch_path, "root@localhost"]
    try:
        for attempt in (1, 2):
            result = subprocess.run(command, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            output = result.stdout.decode(errors="replace")
            if result.returncode == 0 and "Couldn't" not in output:
                break
            if "Permission denied" in output and attempt == 1:
                time.sleep(3)  # dropbear auth throttle, same as ssh_run
                continue
            raise RuntimeError("sftp upload failed: " + output.strip()[-500:])
    finally:
        Path(batch_path).unlink(missing_ok=True)


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


def _preflight(kit_root, port, action):
    try:
        ssh_run(kit_root, port, "echo ready")
    except RuntimeError as exc:
        raise RuntimeError(
            f"cannot reach the ramdisk SSH server on port {port}; boot the "
            "ramdisk first (or check iproxy and the USB cable)") from exc
    for attempt in (1, 2):
        if ssh_command(kit_root, port, "/usr/local/bin/mount-mnt2") == 0:
            break
        if attempt == 1:
            time.sleep(3)  # dropbear auth throttle, same as ssh_run
            continue
        raise RuntimeError("mount-mnt2 failed on the device; /mnt2 must be "
                           f"mounted before {action} activation records")


def _pick_source(kit_root, port, version):
    """Find the tree holding a *_record.plist; the version-appropriate
    location wins, the other one is the fallback."""
    major = int(re.match(r"\d+", version).group())
    candidates = ([MAD_REMOTE, LOCKDOWN_REMOTE] if major >= 8
                  else [LOCKDOWN_REMOTE, MAD_REMOTE])
    fallback = None
    for candidate in candidates:
        try:
            rows = list_tree(kit_root, port, candidate)
        except RuntimeError:
            continue  # path missing on this firmware
        if _has_record(rows):
            return candidate, rows
        if fallback is None:
            fallback = (candidate, rows)
    if fallback is not None and not _has_record(fallback[1]):
        raise RuntimeError(
            f"no *_record.plist under {LOCKDOWN_REMOTE} or {MAD_REMOTE} "
            f"(iOS {version}); the device appears to be unactivated")
    raise RuntimeError(
        f"neither {LOCKDOWN_REMOTE} nor {MAD_REMOTE} exists (iOS {version})")


def dump_activation(kit_root, port, out=None, output_dir=None):
    """Collect the activation Lockdown folder from the running ramdisk.

    Returns (path, info); info carries the human-readable dump summary.
    """
    _preflight(kit_root, port, "dumping")
    version, build = device_version(kit_root, port)
    source, rows = _pick_source(kit_root, port, version)

    source_dir_name = Path(source).name
    staging = Path(tempfile.mkdtemp(prefix="qwq-activation-"))
    mtime = int(time.time())
    try:
        scp_pull(kit_root, port, source, staging)
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

        if out:
            target = Path(out)
        elif output_dir:
            target = Path(output_dir) / f"activation-{version}-{build}.tar"
        else:
            target = Path(f"activation-{version}-{build}.tar")
        target.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(target, "w", format=tarfile.GNU_FORMAT) as tf:
            for name, local, mode, uid, gid, size in sorted(members):
                if local is None:
                    _add_dir(tf, name, mode, uid, gid, mtime)
                else:
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
            "members": len(names),
        }
        return target, info
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def restore_activation(kit_root, port, tar_path):
    """Write a dumped Lockdown folder back to /mnt2/root/Library/Lockdown.

    The live folder is replaced wholesale after being copied to
    Lockdown.bak-<timestamp> on the device.  Returns (path, info).
    """
    tar_path = Path(tar_path)
    if not tar_path.is_file():
        raise FileNotFoundError(f"activation tar not found: {tar_path}")
    _preflight(kit_root, port, "restoring")

    with tarfile.open(tar_path) as tf:
        members = tf.getmembers()
        unsafe = [m.name for m in members
                  if m.name != TAR_ROOT and not m.name.startswith(TAR_ROOT + "/")]
        if unsafe:
            raise RuntimeError(f"tar must contain a single {TAR_ROOT}/ folder; "
                               f"unexpected members: {unsafe[:5]}")
        if not any(m.isfile() and "_record.plist" in m.name for m in members):
            raise RuntimeError(f"no *_record.plist in {tar_path}; refusing to "
                               "restore a tar without an activation record")
        files = [m for m in members if m.isfile()]
        dirs = [m for m in members if m.isdir()]
        staging = Path(tempfile.mkdtemp(prefix="qwq-restore-"))
        for member in files:
            target = staging / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tf.extractfile(member).read())
    try:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        remote_stage = f"/mnt2/tmp/qwq-restore-{stamp}"
        ssh_run(kit_root, port, f'rm -rf "{remote_stage}"')
        dir_rels = [m.name[len(TAR_ROOT):].lstrip("/") for m in dirs]
        file_rels = [m.name[len(TAR_ROOT):].lstrip("/") for m in files]
        sftp_push_tree(kit_root, port, staging / TAR_ROOT,
                       f"{remote_stage}/{TAR_ROOT}", dir_rels, file_rels)

        backup = f"{LOCKDOWN_REMOTE}.bak-{stamp}"
        script = ["set -e"]
        backups = []
        if ssh_run(kit_root, port,
                   f'[ -e "{LOCKDOWN_REMOTE}" ] && echo yes || echo no'
                   ).strip().endswith("yes"):
            script.append(f'cp -R "{LOCKDOWN_REMOTE}" "{backup}"')
            backups.append(backup)
        script += [
            f'rm -rf "{LOCKDOWN_REMOTE}"',
            f'mkdir -p /mnt2/root/Library',
            f'mv "{remote_stage}/{TAR_ROOT}" "{LOCKDOWN_REMOTE}"',
        ]
        # scp did not preserve modes or ownership; replay the tar metadata
        # (directories first, then files, chown before chmod).
        for member in sorted(dirs, key=lambda m: m.name.count("/")) + \
                sorted(files, key=lambda m: m.name.count("/")):
            remote = LOCKDOWN_REMOTE + member.name[len(TAR_ROOT):]
            script.append(f'/usr/sbin/chown {member.uid}:{member.gid} "{remote}"')
            script.append(f'/bin/chmod {member.mode:o} "{remote}"')
        script.append(f'rm -rf "{remote_stage}"')
        ssh_run(kit_root, port, "\n".join(script))

        # Verify what actually landed on /mnt2 against the tar manifest.
        rows = list_tree(kit_root, port, LOCKDOWN_REMOTE)
        expected = {m.name[len(TAR_ROOT):].lstrip("/"): m.size for m in files}
        landed = {rel: size for rel, _, _, _, size, is_dir in rows if not is_dir}
        missing = {name: size for name, size in expected.items()
                   if landed.get(name) != size}
        if missing:
            raise RuntimeError(f"restore verification failed; these tar files "
                               f"are absent or changed on the device: {missing}")
        info = {
            "tar": str(tar_path), "restored": len(files),
            "activation_records": [m.name for m in files
                                   if "_record.plist" in m.name],
            "backups": backups,
        }
        return tar_path, info
    finally:
        shutil.rmtree(staging, ignore_errors=True)
