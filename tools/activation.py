"""Dump and restore activation files over SSH.

Legacy iOS 7/8 archives use a Lockdown/ tree:

    Lockdown/                                        (0700 root:wheel)
    Lockdown/activation_records/activation_record.plist
    Lockdown/data_ark.plist
    Lockdown/device_private_key.pem, device_public_key.pem
    Lockdown/escrow_records/**, Lockdown/pair_records/**

For iOS 9.3+, archives use Legacy-iOS-Kit's private/var/ layout with the
system container's activation_records and internal/data_ark.plist mapped
under root/Library/Lockdown, plus available mobile FairPlay and wireless
activation files. Restore writes each live path after on-device backups.

The iRam userland shipped in the ramdisk (tar, ls -l) is linked against
iOS 9+ libSystem symbols and crashes on the iOS 7 restore ramdisk
(_fdopendir/_clock_gettime lazy binding failures), so nothing is archived
on the device.  find -ls provides the listing, scp pulls files off the
device for dumps, sftp (with directories pre-created through ssh, because
dropbear's sftp-server rejects the realpath of recursive uploads) pushes
files back for restores, and the tar is assembled and verified on the host.
"""
import io
from datetime import datetime
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath

from .boot import ssh_command
from .common import kit_bin

LOCKDOWN_REMOTE = "/mnt2/root/Library/Lockdown"
MAD_REMOTE = "/mnt2/mobile/Library/mad"
SYSTEM_CONTAINERS_REMOTE = "/mnt2/containers/Data/System"
SYSTEM_VERSION_REMOTE = "/mnt1/System/Library/CoreServices/SystemVersion.plist"
TAR_ROOT = "Lockdown"
KIT_LOCKDOWN = "private/var/root/Library/Lockdown"
KIT_EXTRA_PATHS = (
    "mobile/Media/iTunes_Control/iTunes/IC-Info.sidv",
    "mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sisv",
    "wireless/Library/Preferences/com.apple.commcenter.plist",
)
UNAMES = {0: "root", 501: "mobile", 25: "wireless", 4294967294: "nobody"}
GNAMES = {0: "wheel", 501: "mobile", 25: "wireless", 4294967294: "nobody"}
USER_IDS = {name: uid for uid, name in UNAMES.items()}
GROUP_IDS = {name: gid for gid, name in GNAMES.items()}
USER_IDS["_wireless"] = 25
GROUP_IDS["_wireless"] = 25


def _chown_id(value):
    # Darwin reports nobody as unsigned -2; iOS chown rejects 4294967294.
    return "nobody" if value in (-2, 4294967294) else str(value)


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
    ssh_run(kit_root, port,
            f'test -f {SYSTEM_VERSION_REMOTE} || '
            '/sbin/mount_hfs -o ro /dev/disk0s1s1 /mnt1')
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
        if not owner.isdigit() and owner not in USER_IDS:
            raise RuntimeError(f"unknown device file owner in {remote_path}: {owner}")
        if not group.isdigit() and group not in GROUP_IDS:
            raise RuntimeError(f"unknown device file group in {remote_path}: {group}")
        uid = int(owner) if owner.isdigit() else USER_IDS[owner]
        gid = int(group) if group.isdigit() else GROUP_IDS[group]
        rows.append((path[len(remote_path):].lstrip("/"), bits, uid, gid,
                     int(size), mode.startswith("d")))
    return rows


def _has_record(rows):
    return any(rel.endswith("_record.plist") for rel, _, _, _, _, is_dir in rows
               if not is_dir)


def _uses_system_container(version):
    parts = [int(part) for part in version.split(".")[:2]]
    return parts[0] > 9 or (parts[0] == 9 and len(parts) > 1 and parts[1] >= 3)


def _system_containers(kit_root, port, filename, suffix_pattern):
    """Find exact system container paths, without reading file contents."""
    output = ssh_run(kit_root, port,
                     f'find {SYSTEM_CONTAINERS_REMOTE} -type f -name "{filename}"')
    pattern = re.compile(
        rf"^{re.escape(SYSTEM_CONTAINERS_REMOTE)}/[0-9A-Fa-f-]{{36}}"
        rf"{suffix_pattern}$")
    return sorted({path.split("/Library/", 1)[0] for path in output.splitlines()
                   if pattern.fullmatch(path)})


def _system_container(kit_root, port, *, require_record):
    if require_record:
        roots = _system_containers(kit_root, port, "*_record.plist",
                                   r"/Library/activation_records/[^/]+_record\.plist")
    else:
        roots = _system_containers(kit_root, port, "data_ark.plist",
                                   r"/Library/internal/data_ark\.plist")
    if len(roots) != 1:
        kind = "activation record" if require_record else "internal/data_ark.plist"
        raise RuntimeError(f"expected one iOS system container with {kind}; "
                           f"found {len(roots)}")
    return roots[0]


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


def _pick_legacy_source(kit_root, port, version):
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


def _dump_sources(kit_root, port, version):
    """Return (remote path, tar path, listing) for each activation source."""
    if not _uses_system_container(version):
        source, rows = _pick_legacy_source(kit_root, port, version)
        return [(source, TAR_ROOT, rows)]
    root = _system_container(kit_root, port, require_record=True)
    records = root + "/Library/activation_records"
    ark = root + "/Library/internal/data_ark.plist"
    if ssh_run(kit_root, port, f'test -f "{ark}" && echo yes || echo no').strip() != "yes":
        raise RuntimeError(f"activation record exists, but {ark} is missing")
    record_rows = list_tree(kit_root, port, records)
    if not _has_record(record_rows):
        raise RuntimeError(f"no *_record.plist under {records}")
    sources = [(records, KIT_LOCKDOWN + "/activation_records", record_rows),
               (ark, KIT_LOCKDOWN + "/data_ark.plist", list_tree(kit_root, port, ark))]
    for rel in KIT_EXTRA_PATHS:
        remote = "/mnt2/" + rel
        if ssh_run(kit_root, port,
                   f'test -f "{remote}" && echo yes || echo no').strip() == "yes":
            sources.append((remote, "private/var/" + rel,
                            list_tree(kit_root, port, remote)))
    return sources


def _add_system_tar_parents(members):
    """Add the parent directories Legacy-iOS-Kit creates before archiving."""
    existing = {name for name, *_ in members}
    for name in list(existing):
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            path = str(parent)
            if path not in existing:
                uid = (501 if path.startswith("private/var/mobile") else
                       25 if path.startswith("private/var/wireless") else 0)
                members.append((path, None, 0o755, uid, uid, 0))
                existing.add(path)
            parent = parent.parent


def dump_activation(kit_root, port, out=None, output_dir=None):
    """Collect activation files from the running ramdisk.

    Returns (path, info); info carries the human-readable dump summary.
    """
    _preflight(kit_root, port, "dumping")
    version, build = device_version(kit_root, port)
    sources = _dump_sources(kit_root, port, version)
    staging = Path(tempfile.mkdtemp(prefix="qwq-activation-"))
    mtime = int(time.time())
    try:
        members = []  # (tar_path, local_or_None, mode, uid, gid, size)
        for index, (source, prefix, rows) in enumerate(sources):
            dest = staging / str(index)
            dest.mkdir()
            is_root_file = len(rows) == 1 and not rows[0][-1] and rows[0][0] == ""
            scp_pull(kit_root, port, source, dest, recursive=not is_root_file)
            for rel, mode, uid, gid, size, is_dir in rows:
                tar_path = f"{prefix}/{rel}" if rel else prefix
                if is_dir:
                    members.append((tar_path, None, mode, uid, gid, 0))
                    continue
                local = dest / Path(source).name / rel
                # scp can retain a 000 mode even without -p. The tar uses
                # the remote listing above, so open only the temporary copy.
                local.chmod(local.stat().st_mode | 0o400)
                if not local.is_file() or local.stat().st_size != size:
                    raise RuntimeError(f"pulled copy of {rel} does not match the "
                                       f"device listing ({size} bytes expected)")
                members.append((tar_path, local, mode, uid, gid, size))
        if _uses_system_container(version):
            members.append(("private/var/mobile/Library/Preferences", None,
                            0o755, 501, 501, 0))
            _add_system_tar_parents(members)

        timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
        default_name = f"{timestamp}-activation-{version}-{build}.tar"
        if out:
            target = Path(out)
        elif output_dir:
            target = Path(output_dir) / default_name
        else:
            target = Path(default_name)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation prevents an earlier dump from being overwritten.
        # Remove only our new archive if packing or verification fails.
        created = False
        try:
            with tarfile.open(target, "x", format=tarfile.GNU_FORMAT) as tf:
                created = True
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
        except BaseException:
            if created:
                target.unlink(missing_ok=True)
            raise
        info = {
            "version": version, "build": build, "source": sources[0][0],
            "activation_records": records,
            "record_files": sum(1 for _, local, *_ in members if local is not None),
            "members": len(names),
        }
        return target, info
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _restore_system_container(kit_root, port, staging, files, dirs, stamp,
                              kit_layout):
    """Restore iOS 9.3+ files from either Kit or older Lockdown-only tars."""
    tar_root = "private" if kit_layout else TAR_ROOT
    record_prefix = (KIT_LOCKDOWN if kit_layout else TAR_ROOT) + "/activation_records"
    ark_name = (KIT_LOCKDOWN if kit_layout else TAR_ROOT) + "/data_ark.plist"
    extras = {"private/var/" + rel: "/mnt2/" + rel for rel in KIT_EXTRA_PATHS}
    parent_dirs = {tar_root, record_prefix}
    if kit_layout:
        parent_dirs.add("private/var/mobile/Library/Preferences")
    for name in (record_prefix, ark_name, *(extras if kit_layout else ())):
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            parent_dirs.add(str(parent))
            parent = parent.parent
    unexpected = [m.name for m in files + dirs
                  if not ((m.isfile() and
                           (m.name == ark_name or m.name.startswith(record_prefix + "/")
                            or (kit_layout and m.name in extras)))
                          or (m.isdir() and
                              (m.name in parent_dirs or
                               m.name.startswith(record_prefix + "/"))))]
    if unexpected:
        raise RuntimeError(f"unexpected iOS 9.3+ activation tar members: {unexpected[:5]}")
    if not any(m.name == ark_name for m in files):
        raise RuntimeError(f"iOS 9.3+ restore requires {ark_name}")
    if not any(m.name.startswith(record_prefix + "/") and
               m.name.endswith("_record.plist") for m in files):
        raise RuntimeError("iOS 9.3+ restore requires an activation record")

    root = _system_container(kit_root, port, require_record=False)
    records = root + "/Library/activation_records"
    ark = root + "/Library/internal/data_ark.plist"
    remote_stage = f"/mnt2/tmp/qwq-restore-{stamp}"
    dir_rels = {m.name[len(tar_root):].lstrip("/") for m in dirs}
    file_rels = [m.name[len(tar_root):].lstrip("/") for m in files]
    for rel in file_rels:
        parent = PurePosixPath(rel).parent
        while str(parent) != ".":
            dir_rels.add(str(parent))
            parent = parent.parent
    sftp_push_tree(kit_root, port, staging / tar_root,
                   f"{remote_stage}/{tar_root}", sorted(dir_rels), file_rels)

    file_targets = {ark_name: ark}
    file_targets.update({name: path for name, path in extras.items()
                         if kit_layout and any(m.name == name for m in files)})
    backups = []
    script = ["set -e"]
    for path in (records, *file_targets.values()):
        exists = ssh_run(kit_root, port,
                         f'[ -e "{path}" ] && echo yes || echo no').strip()
        if exists == "yes":
            backup = path + f".bak-{stamp}"
            script.append(f'cp -R "{path}" "{backup}"')
            backups.append(backup)
    script += [
        f'rm -rf "{records}"',
        f'mv "{remote_stage}/{record_prefix}" "{records}"',
    ]
    for name, path in file_targets.items():
        script.append(f'mkdir -p "{str(PurePosixPath(path).parent)}"')
        script.append(f'mv "{remote_stage}/{name}" "{path}"')
    for member in sorted(dirs, key=lambda m: m.name.count("/")) + \
            sorted(files, key=lambda m: m.name.count("/")):
        if member.name == record_prefix or member.name.startswith(record_prefix + "/"):
            remote = records + member.name[len(record_prefix):]
        elif member.name in file_targets:
            remote = file_targets[member.name]
        else:
            continue  # Do not change existing parent directory ownership/mode.
        script.append(f'/usr/sbin/chown {_chown_id(member.uid)}:'
                      f'{_chown_id(member.gid)} "{remote}"')
        script.append(f'/bin/chmod {member.mode:o} "{remote}"')
    script.append(f'rm -rf "{remote_stage}"')
    ssh_run(kit_root, port, "\n".join(script))

    rows = list_tree(kit_root, port, records)
    landed = {rel: (mode, uid, gid, size, is_dir)
              for rel, mode, uid, gid, size, is_dir in rows}
    mismatched = []
    for member in files + dirs:
        if member.name != record_prefix and not member.name.startswith(record_prefix + "/"):
            continue
        rel = member.name[len(record_prefix):].lstrip("/")
        actual = landed.get(rel)
        if (actual is None or actual[:3] != (member.mode, member.uid, member.gid)
                or actual[4] != member.isdir()
                or (member.isfile() and actual[3] != member.size)):
            mismatched.append(member.name)
    for name, path in file_targets.items():
        rows = list_tree(kit_root, port, path)
        actual = next(((mode, uid, gid, size) for rel, mode, uid, gid, size, is_dir
                       in rows if rel == "" and not is_dir), None)
        member = next(m for m in files if m.name == name)
        if actual != (member.mode, member.uid, member.gid, member.size):
            mismatched.append(name)
    if mismatched:
        raise RuntimeError("restore verification failed for device metadata: "
                           f"{mismatched}")
    return backups


def restore_activation(kit_root, port, tar_path):
    """Restore a dumped activation tar to the device version's paths.

    Existing paths are backed up on the device before replacement.
    Returns (path, info).
    """
    tar_path = Path(tar_path)
    if not tar_path.is_file():
        raise FileNotFoundError(f"activation tar not found: {tar_path}")
    _preflight(kit_root, port, "restoring")
    version, _ = device_version(kit_root, port)

    with tarfile.open(tar_path) as tf:
        members = tf.getmembers()
        kit_layout = any(m.name == "private" or m.name.startswith("private/")
                         for m in members)
        if kit_layout and not _uses_system_container(version):
            raise RuntimeError("Kit-style activation tar requires iOS 9.3 or newer")
        def valid_root(name):
            if kit_layout:
                return name in ("private", "private/var") or name.startswith("private/var/")
            return name == TAR_ROOT or name.startswith(TAR_ROOT + "/")
        unsafe = [m.name for m in members
                  if not valid_root(m.name)
                  or any(part in (".", "..") for part in PurePosixPath(m.name).parts)
                  or re.fullmatch(r"[A-Za-z0-9_./-]+", m.name) is None
                  or not (m.isfile() or m.isdir())]
        if unsafe:
            raise RuntimeError(f"unexpected activation tar members: {unsafe[:5]}")
        names = [m.name for m in members]
        if len(names) != len(set(names)):
            raise RuntimeError("activation tar contains duplicate paths")
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
        if _uses_system_container(version):
            stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S-%f")
            backups = _restore_system_container(kit_root, port, staging,
                                                files, dirs, stamp, kit_layout)
            return tar_path, {
                "tar": str(tar_path), "restored": len(files),
                "activation_records": [m.name for m in files
                                       if m.name.endswith("_record.plist")],
                "backups": backups,
            }
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
            script.append(f'/usr/sbin/chown {_chown_id(member.uid)}:'
                          f'{_chown_id(member.gid)} "{remote}"')
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
