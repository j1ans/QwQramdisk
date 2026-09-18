import json
import urllib.request
from pathlib import Path
from .common import kit_bin, manifest_path, run, select_identity
from .profiles import get_profile

IPSW_API = "https://api.ipsw.me/v4/device/{device}?type=ipsw"
KEYS_BASE = "https://raw.githubusercontent.com/LukeZGD/Legacy-iOS-Kit-Keys/af6bf5934dc61ed557a967a3f42ab7fb8ed8c45e/{device}/{build}/index.html"


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "qwqramdisk/1.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def resolve_firmware(profile):
    p = get_profile(profile)
    doc = get_json(IPSW_API.format(device=p["device"]))
    for fw in doc["firmwares"]:
        if fw["version"] == p["version"] and fw["buildid"] == p["build"]:
            return fw
    raise ValueError(f"firmware not found: {p['device']} {p['version']} {p['build']}")


def resolve_keys(profile):
    p = get_profile(profile)
    doc = get_json(KEYS_BASE.format(device=p["device"], build=p["build"]))
    if doc.get("identifier") != p["device"] or doc.get("buildid") != p["build"]:
        raise ValueError("firmware-key metadata identity mismatch")
    return doc


def key_for(keys, image):
    for item in keys["keys"]:
        if item["image"].lower() == image.lower():
            return item
    raise ValueError(f"firmware keys do not contain {image}")


def pzb_get(kit_root, url, member, output, atomic=False):
    output = Path(output)
    complete = output.with_name(output.name + ".complete")
    if output.is_file() and output.stat().st_size and (not atomic or complete.is_file()):
        return output
    output.parent.mkdir(parents=True, exist_ok=True)
    target = output
    if atomic:
        target = output.with_name(output.name + ".partial")
        if target.exists():
            target.unlink()
        if output.exists() and not complete.exists():
            output.unlink()
    # pzb treats -o as a basename and writes into its current directory.
    run([kit_bin(kit_root, "pzb"), "-g", member, "-o", target.name, url],
        cwd=output.parent)
    if not target.is_file() or not target.stat().st_size:
        raise RuntimeError(f"pzb did not create {target}")
    if atomic:
        target.replace(output)
        complete.write_text("complete\n")
    return output


def fetch_components(kit_root, cache, profile="n53-12F70"):
    cache = Path(cache); cache.mkdir(parents=True, exist_ok=True)
    fw = resolve_firmware(profile); keys = resolve_keys(profile)
    (cache / "firmware.json").write_text(json.dumps(fw, indent=2) + "\n")
    (cache / "keys.json").write_text(json.dumps(keys, indent=2) + "\n")
    bm = pzb_get(kit_root, fw["url"], "BuildManifest.plist", cache / "BuildManifest.plist")
    p = get_profile(profile)
    identity = select_identity(bm, p["device"], p["board"])
    components = {
        "iBSS": manifest_path(identity, "iBSS"),
        "iBEC": manifest_path(identity, "iBEC"),
        "Kernelcache": manifest_path(identity, "KernelCache"),
        "DeviceTree": manifest_path(identity, "DeviceTree"),
        "RestoreRamdisk": manifest_path(identity, "RestoreRamDisk"),
    }
    outputs = {"BuildManifest": bm}
    for image, member in components.items():
        outputs[image] = pzb_get(
            kit_root, fw["url"], member,
            cache / "encrypted" / Path(member).name)
    return fw, keys, outputs
