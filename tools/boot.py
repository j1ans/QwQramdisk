import json
import os
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path
from .common import kit_bin, run, sha256
from .profiles import get_profile


def verify(output):
    output = Path(output)
    manifest = json.loads((output / "manifest.json").read_text())
    for name, expected in manifest["artifacts"].items():
        got = sha256(output / name)
        if got != expected:
            raise ValueError(f"artifact digest mismatch: {name}")
    return manifest


def _irecovery_retry(irecovery, arguments, label, retries, delay):
    command = [str(irecovery), *[str(item) for item in arguments]]
    last = None
    for attempt in range(1, retries + 1):
        result = subprocess.run(command)
        if result.returncode == 0:
            return
        last = result.returncode
        if attempt < retries:
            wait = delay + attempt - 1
            print(f"[usb] {label} failed ({attempt}/{retries}); "
                  f"waiting {wait}s before retry", file=sys.stderr)
            time.sleep(wait)
    raise subprocess.CalledProcessError(last, command)


def _query_dfu(irecovery):
    result = subprocess.run(
        [str(irecovery), "-q"], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, result.stdout + result.stderr


def _wait_dfu_query(irecovery, attempts=3, delay=2):
    last_status, last_query = 1, ""
    for attempt in range(1, attempts + 1):
        last_status, last_query = _query_dfu(irecovery)
        if last_status == 0:
            return last_status, last_query
        if attempt < attempts:
            time.sleep(delay)
    return last_status, last_query


def _pwn_retry(kit_root, output, irecovery, profile, retries, delay):
    apple_silicon = os.uname().sysname == "Darwin" and os.uname().machine == "arm64"
    exploit = profile["exploit"]
    if exploit == "ipwnder" and apple_silicon:
        (output / "image3").mkdir(exist_ok=True)
        command = [str(kit_bin(kit_root, "ipwnder")), "-pv"]
    elif exploit == "ipwnder":
        command = [str(kit_bin(kit_root, "ipwnder")), "-p"]
    elif exploit == "gaster":
        command = [str(kit_bin(kit_root, "gaster")), "pwn"]
    else:
        raise ValueError(f"unsupported DFU exploit: {exploit}")

    last = None
    for attempt in range(1, retries + 1):
        result = subprocess.run(command, cwd=output)
        last = result.returncode
        if exploit == "gaster" or (result.returncode == 0 and apple_silicon):
            # ipwnder_lite on A7 and gaster on A8 need a USB reset before
            # irecovery can communicate with the pwned DFU interface.
            subprocess.run([str(kit_bin(kit_root, "gaster")), "reset"],
                           check=False)
        time.sleep(2)
        # Both a failed heap attempt and gaster's successful reset can briefly
        # remove the DFU interface.  Give macOS several enumeration windows
        # before deciding that the user must re-enter DFU manually.
        status, query = _wait_dfu_query(
            irecovery, attempts=3, delay=max(1, min(delay, 3)))
        if status == 0 and "PWND" in query:
            return query
        if status != 0:
            raise RuntimeError(
                "DFU exploit lost the USB device; re-enter normal DFU and retry")
        if "MODE: DFU" not in query:
            raise RuntimeError("device left DFU mode during exploitation")
        if attempt < retries:
            wait = delay + attempt - 1
            print(f"[usb] DFU exploit failed ({attempt}/{retries}); "
                  f"device is still in DFU, waiting {wait}s before retry",
                  file=sys.stderr)
            time.sleep(wait)
    raise subprocess.CalledProcessError(last, command)


def boot(kit_root, output, port=2236, remote_port=22, usb_delay=4,
         retries=5):
    output = Path(output).resolve()
    manifest = verify(output)
    profile = get_profile(manifest["profile"])
    irecovery = kit_bin(kit_root, "irecovery")
    query = run([irecovery, "-q"], capture=True)
    expected = (
        f"CPID: 0x{profile['cpid']:04X}",
        f"BDID: 0x{profile['bdid']:02X}",
        f"PRODUCT: {profile['device']}",
        f"MODEL: {profile['board']}",
        "MODE: DFU",
    )
    missing = [item for item in expected if item.lower() not in query.lower()]
    if missing:
        raise RuntimeError(
            f"expected {profile['device']}/{profile['board']} in DFU mode; "
            f"device query does not match: {', '.join(missing)}")
    if "PWND" not in query:
        query = _pwn_retry(
            kit_root, output, irecovery, profile, retries, usb_delay)
    _irecovery_retry(irecovery, ["-f", output / "iBSS.im4p"],
                     "iBSS send", retries, usb_delay)
    time.sleep(max(8, usb_delay))
    _irecovery_retry(irecovery, ["-f", output / "iBEC.im4p"],
                     "iBEC send", retries, usb_delay)
    # A7 disconnects and enumerates a new USB interface after iBEC.  Some
    # hosts need considerably longer than irecovery's own five-second wait.
    time.sleep(max(12, usb_delay * 2))
    for name, command in [
        ("RestoreRamdisk.img4", "ramdisk"),
        ("DeviceTree.img4", "devicetree"),
        ("Kernelcache.img4", "bootx"),
    ]:
        _irecovery_retry(irecovery, ["-f", output / name],
                         f"{name} send", retries, usb_delay)
        time.sleep(usb_delay)
        _irecovery_retry(irecovery, ["-c", command],
                         f"{command} command", retries, usb_delay)
        time.sleep(usb_delay)
    start_iproxy(kit_root, output, port, remote_port)
    return wait_ssh(kit_root, port, 45)


def _port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _iproxy_processes():
    listing = subprocess.run(
        ["ps", "-axo", "pid=,command="], text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    found = []
    for line in listing.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or "iproxy" not in fields[1]:
            continue
        try:
            pid = int(fields[0])
            argv = shlex.split(fields[1])
        except (ValueError, IndexError):
            continue
        if not argv or Path(argv[0]).name != "iproxy":
            continue
        mappings = []
        for index, arg in enumerate(argv[1:], 1):
            if ":" in arg:
                pair = arg.rsplit(":", 1)
                if all(item.isdigit() for item in pair):
                    mappings.append((int(pair[0]), int(pair[1])))
            elif (arg.isdigit() and index + 1 < len(argv)
                  and argv[index + 1].isdigit()):
                mappings.append((int(arg), int(argv[index + 1])))
        found.append((pid, fields[1], mappings))
    return found


def _stop_process(pid):
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        return
    for _ in range(30):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass


def start_iproxy(kit_root, output, port, remote_port=22):
    output = Path(output)
    pid_path = output / "iproxy.pid"
    processes = _iproxy_processes()
    for pid, _, mappings in processes:
        if (port, remote_port) in mappings and _port_open(port):
            pid_path.write_text(str(pid) + "\n")
            return
    for pid, _, mappings in processes:
        if any(local == port for local, _ in mappings):
            _stop_process(pid)
    if _port_open(port):
        try:
            owner = subprocess.run(
                ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            ).stdout.strip()
        except FileNotFoundError:
            owner = ""
        raise RuntimeError(
            f"local port {port} is occupied by a non-iproxy process"
            + (f":\n{owner}" if owner else ""))
    log_path = output / "iproxy.log"
    log = log_path.open("wb")
    proc = subprocess.Popen([str(kit_bin(kit_root, "iproxy")), str(port), str(remote_port)],
                            stdout=log, stderr=subprocess.STDOUT,
                            start_new_session=True)
    time.sleep(1)
    if proc.poll() is not None:
        log.close()
        detail = log_path.read_text(errors="replace").strip()
        raise RuntimeError("iproxy exited" + (f": {detail}" if detail else ""))
    pid_path.write_text(str(proc.pid) + "\n")


def wait_ssh(kit_root, port, timeout):
    sshpass = kit_bin(kit_root, "sshpass")
    deadline = time.time() + timeout
    cmd = [sshpass, "-p", "alpine", "ssh", "-p", str(port),
           "-o", "PreferredAuthentications=password",
           "-o", "PubkeyAuthentication=no",
           "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=2", "root@localhost", "echo SSH_READY"]
    authentication_rejected = False
    last_error = ""
    while time.time() < deadline:
        p = subprocess.run([str(x) for x in cmd], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True)
        if p.returncode == 0 and "SSH_READY" in p.stdout:
            return True
        last_error = p.stderr.strip()
        if "Permission denied" in p.stderr:
            authentication_rejected = True
        time.sleep(1)
    if authentication_rejected:
        raise RuntimeError(
            "SSH server is reachable but root/alpine authentication was "
            "rejected; verify master.passwd and that root uses a shell "
            "accepted by this Dropbear build")
    if last_error:
        print(f"[ssh] last probe: {last_error}", file=sys.stderr)
    return False


def ssh_command(kit_root, port, remote, interactive=False):
    cmd = [kit_bin(kit_root, "sshpass"), "-p", "alpine", "ssh", "-p", str(port),
           "-o", "PreferredAuthentications=password",
           "-o", "PubkeyAuthentication=no",
           "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "root@localhost"]
    if remote:
        cmd.append(remote)
    if interactive:
        os.execv(str(cmd[0]), [str(x) for x in cmd])
    return subprocess.run([str(x) for x in cmd]).returncode
