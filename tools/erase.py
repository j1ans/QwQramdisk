"""Arm the iOS 9+ erase path using the ramdisk's NVRAM utility."""

from .activation import device_version, ssh_run


def arm_nvram_erase(kit_root, port):
    version, build = device_version(kit_root, port)
    if int(version.split(".", 1)[0]) < 9:
        raise ValueError(f"nvram-erase requires iOS 9 or newer; installed version is {version}")
    ssh_run(kit_root, port, "/usr/sbin/nvram oblit-inprogress=5")
    readback = ssh_run(kit_root, port, "/usr/sbin/nvram oblit-inprogress")
    if readback.split()[-1:] != ["5"]:
        raise RuntimeError("oblit-inprogress NVRAM readback did not equal 5")
    return {"version": version, "build": build,
            "setting": "oblit-inprogress=5"}
