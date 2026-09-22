"""Arm or clear the springboard device lock through its preference plist.

Both commands pull /mnt2/mobile/Library/Preferences/com.apple.springboard.plist,
edit it on the host with plistlib, and push it back with the original mode
and ownership (0600 mobile:mobile on device), keeping an on-device
.bak-<timestamp> copy.  The edit is verified by re-reading the pushed file
before the command reports success.

lock-wipe arms the wipe path: SBDeviceLockFailedAttempts=721 and
SBDeviceWipeEnabled=true.  On the next normal boot springboard sees the
failed-attempt counter far past the wipe threshold with wiping enabled.

remove-disabled clears the disabled state instead: the counter is set to
-9999, every other SBDevice* key is dropped (wipe enable, lock blocked, ...),
and every LockoutState* file in /mnt2/mobile/Library/SpringBoard is deleted.
"""
import plistlib
import shutil
import tempfile
import time
from pathlib import Path

from .activation import _preflight, scp_pull, ssh_run, sftp_push_tree

PLIST_REMOTE = "/mnt2/mobile/Library/Preferences/com.apple.springboard.plist"
PLIST_NAME = "com.apple.springboard.plist"
SPRINGBOARD_REMOTE = "/mnt2/mobile/Library/SpringBoard"
ATTEMPTS_KEY = "SBDeviceLockFailedAttempts"
WIPE_KEY = "SBDeviceWipeEnabled"
WIPE_ATTEMPTS = 721
CLEAR_ATTEMPTS = -9999


def _pull_plist(kit_root, port, staging):
    stat = ssh_run(kit_root, port,
                   f'/usr/bin/stat -f "%p %u %g %z" "{PLIST_REMOTE}"').split()
    mode = int(stat[0], 8) & 0o7777  # %p includes the file type bits
    uid, gid, size = int(stat[1]), int(stat[2]), int(stat[3])
    scp_pull(kit_root, port, PLIST_REMOTE, staging, recursive=False)
    local = staging / PLIST_NAME
    if not local.is_file() or local.stat().st_size != size:
        raise RuntimeError(f"pulled {PLIST_NAME} does not match the device "
                           f"listing ({size} bytes expected)")
    return local, mode, uid, gid


def _push_plist(kit_root, port, staging, mode, uid, gid):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{PLIST_REMOTE}.bak-{stamp}"
    ssh_run(kit_root, port, f'cp "{PLIST_REMOTE}" "{backup}"')
    remote_dir = str(Path(PLIST_REMOTE).parent)
    sftp_push_tree(kit_root, port, staging, remote_dir, [], [PLIST_NAME])
    ssh_run(kit_root, port,
            f'/usr/sbin/chown {uid}:{gid} "{PLIST_REMOTE}"; '
            f'/bin/chmod {mode:o} "{PLIST_REMOTE}"')
    return backup


def _read_device_plist(kit_root, port, staging):
    local, _, _, _ = _pull_plist(kit_root, port, staging)
    return plistlib.loads(local.read_bytes())


def _edit_plist(kit_root, port, mutate, action):
    """Shared pull → mutate → push → verify flow; returns the report dict."""
    _preflight(kit_root, port, action)
    staging = Path(tempfile.mkdtemp(prefix=f"qwq-{action.replace('-', '')}-"))
    try:
        local, mode, uid, gid = _pull_plist(kit_root, port, staging)
        doc = plistlib.loads(local.read_bytes())
        report = mutate(doc)
        local.write_bytes(plistlib.dumps(doc, fmt=plistlib.FMT_BINARY,
                                         sort_keys=True))
        report["backup"] = _push_plist(kit_root, port, staging, mode, uid, gid)

        verify = Path(tempfile.mkdtemp(prefix="qwq-sbverify-"))
        try:
            pushed = _read_device_plist(kit_root, port, verify)
            for key, value in report["set"].items():
                if pushed.get(key) != value:
                    raise RuntimeError(f"verification failed: {key} is "
                                       f"{pushed.get(key)!r}, expected {value!r}")
            for key in report["removed"]:
                if key in pushed:
                    raise RuntimeError(f"verification failed: {key} still present")
        finally:
            shutil.rmtree(verify, ignore_errors=True)
        return report
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def lock_wipe(kit_root, port):
    """Arm the springboard wipe: 721 failed attempts + wipe enabled."""

    def mutate(doc):
        doc[ATTEMPTS_KEY] = WIPE_ATTEMPTS
        doc[WIPE_KEY] = True
        return {
            "action": "lock-wipe",
            "set": {ATTEMPTS_KEY: WIPE_ATTEMPTS, WIPE_KEY: True},
            "removed": [],
        }

    return _edit_plist(kit_root, port, mutate, "arming")


def remove_disabled(kit_root, port):
    """Clear the disabled state: counter -9999, drop SBDevice* keys and
    LockoutState* files."""
    def mutate(doc):
        removed = sorted(key for key in doc
                         if key.startswith("SBDevice") and key != ATTEMPTS_KEY)
        for key in removed:
            del doc[key]
        doc[ATTEMPTS_KEY] = CLEAR_ATTEMPTS
        return {
            "action": "remove-disabled",
            "set": {ATTEMPTS_KEY: CLEAR_ATTEMPTS},
            "removed": removed,
        }

    report = _edit_plist(kit_root, port, mutate, "clearing")
    lockouts = ssh_run(kit_root, port,
                       f'cd "{SPRINGBOARD_REMOTE}" 2>/dev/null && '
                       'for f in LockoutState*; do [ -e "$f" ] && echo "$f"; done; true')
    deleted = [line for line in lockouts.splitlines() if line.strip()]
    if deleted:
        ssh_run(kit_root, port, "set -e; " + "; ".join(
            f'rm -f "{SPRINGBOARD_REMOTE}/{name}"' for name in deleted))
    report["lockout_files_deleted"] = deleted
    return report
