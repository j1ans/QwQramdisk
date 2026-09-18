"""Identify a connected recovery/DFU device and select its firmware profile."""
import re

from .common import kit_bin, run
from .profiles import PROFILES


def query_device(kit_root, require_dfu=False):
    try:
        text = run([kit_bin(kit_root, "irecovery"), "-q"], capture=True)
    except Exception as exc:
        raise RuntimeError("no recovery/DFU device detected") from exc
    fields = dict(re.findall(r"^([A-Z]+):\s*(.*?)\s*$", text, re.MULTILINE))
    required = ("CPID", "BDID", "PRODUCT", "MODEL", "MODE")
    missing = [name for name in required if not fields.get(name)]
    if missing:
        raise RuntimeError(f"irecovery output lacks: {', '.join(missing)}")
    if require_dfu and fields["MODE"] != "DFU":
        raise RuntimeError(f"device must be in DFU mode, current mode: {fields['MODE']}")
    return fields


def select_profile(kit_root, version, require_dfu=False):
    device = query_device(kit_root, require_dfu)
    matches = [name for name, p in PROFILES.items()
               if p["version"] == version
               and p["device"] == device["PRODUCT"]
               and p["board"].lower() == device["MODEL"].lower()]
    if len(matches) != 1:
        raise ValueError(
            f"no unique iOS {version} profile for {device['PRODUCT']}/{device['MODEL']}")
    return matches[0], device
