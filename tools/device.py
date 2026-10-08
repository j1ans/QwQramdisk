"""Identify a connected recovery/DFU device and select its firmware profile."""
import re

from .common import kit_bin, run
from .fetch import get_json
from .profiles import PROFILES, register_dynamic_profile


IPSW_API = "https://api.ipsw.me/v4/device/{device}?type=ipsw"


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
    if len(matches) == 1:
        return matches[0], device
    if len(matches) > 1:
        raise ValueError(
            f"multiple iOS {version} builds for {device['PRODUCT']}/{device['MODEL']}: "
            f"{', '.join(sorted(matches))}; select the installed build with --profile")

    # Resolve a new A7/A8/A8X board from the connected DFU device and its IPSW.
    catalog = get_json(IPSW_API.format(device=device["PRODUCT"]))
    firmwares = [fw for fw in catalog.get("firmwares", [])
                 if fw.get("version") == version]
    if len(firmwares) != 1:
        raise ValueError(
            f"no unique IPSW for {device['PRODUCT']}/{device['MODEL']} iOS {version}")
    return register_dynamic_profile(device, version, firmwares[0]), device
