import hashlib
import json
import plistlib
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path
from .common import kit_bin, manifest_path, progress, run, select_identity, sha256
from .fetch import fetch_components, key_for
from .patch_ibec import patch as patch_ibec
from .patch_ibss import patch as patch_ibss
from .patch_kernel import patch as patch_kernel
from .ios9_pattern import (pack_stock_kernel,
                           patch_stage as patch_ios9_stage)
from .profiles import get_profile

IRAM_URL = "https://github.com/LukeZGD/Legacy-iOS-Kit/files/14952123/iram.zip"


def ensure_iram(tools_root, cache, allow_download=True):
    tools_root, cache = Path(tools_root), Path(cache)
    bundled = tools_root / "resources/iram.tar"
    if bundled.is_file():
        return bundled
    target = cache / "iram.tar"
    if target.is_file():
        return target
    if not allow_download:
        raise FileNotFoundError("offline build requires a local iram.tar")
    archive = cache / "iram.zip"
    cache.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(IRAM_URL, archive)
    with zipfile.ZipFile(archive) as zf:
        names = [x for x in zf.namelist() if Path(x).name == "iram.tar"]
        if len(names) != 1:
            raise ValueError("iram.zip does not contain one iram.tar")
        with zf.open(names[0]) as src, target.open("wb") as dst:
            shutil.copyfileobj(src, dst)
    return target


def decrypt_img4(img4, source, output, item, decompress=False):
    iv, key = item.get("iv", ""), item.get("key", "")
    if not iv or not key:
        raise ValueError(f"missing IV/key for {item.get('image')}")
    args = [img4, "-i", source, "-o", output, "-k", iv + key]
    if decompress:
        args.append("-D")
    run(args)


def hfs(hfsplus, image, *args):
    result = subprocess.run([str(hfsplus), str(image), *[str(x) for x in args]],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    if result.returncode:
        raise RuntimeError(f"hfsplus {args[0]} failed: {result.stdout[-800:]}")


def verify_hfs_file(hfsplus, image, image_path, expected, scratch):
    scratch = Path(scratch)
    if scratch.exists():
        scratch.unlink()
    hfs(hfsplus, image, "extract", image_path, scratch)
    if not scratch.is_file() or scratch.read_bytes() != Path(expected).read_bytes():
        raise RuntimeError(f"ramdisk injection verification failed: {image_path}")


def wrap(img4, ticket, source, output, image_type):
    run([img4, "-i", source, "-o", output, "-M", ticket,
         "-T", image_type, "-A"])


def cached_components(cache, profile):
    """Load and verify all firmware inputs for a network-free build."""
    cache = Path(cache)
    if not cache.is_dir():
        raise FileNotFoundError(f"offline firmware cache is missing: {cache}")
    p = get_profile(profile)
    fw = json.loads((cache / "firmware.json").read_text())
    keys = json.loads((cache / "keys.json").read_text())
    if (fw.get("identifier"), fw.get("version"), fw.get("buildid")) != (
            p["device"], p["version"], p["build"]):
        raise ValueError(f"cached firmware does not match {profile}")
    if (keys.get("identifier"), keys.get("buildid")) != (
            p["device"], p["build"]):
        raise ValueError(f"cached firmware keys do not match {profile}")
    bm = cache / "BuildManifest.plist"
    manifest = plistlib.loads(bm.read_bytes())
    if (manifest.get("ProductVersion") != p["version"]
            or manifest.get("ProductBuildVersion") != p["build"]
            or p["device"] not in manifest.get("SupportedProductTypes", [])):
        raise ValueError(f"cached BuildManifest does not match {profile}")
    identity = select_identity(bm, p["device"], p["board"])
    if (int(str(identity["ApChipID"]), 0) != p["cpid"]
            or int(str(identity["ApBoardID"]), 0) != p["bdid"]):
        raise ValueError(f"cached BuildManifest hardware does not match {profile}")
    sources = {"BuildManifest": bm}
    for image, component in (("iBSS", "iBSS"), ("iBEC", "iBEC"),
                             ("Kernelcache", "KernelCache"),
                             ("DeviceTree", "DeviceTree"),
                             ("RestoreRamdisk", "RestoreRamDisk")):
        member = identity["Manifest"][component]
        source = cache / "encrypted" / Path(manifest_path(identity, component)).name
        digest = hashlib.sha1()
        with source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.digest() != member["Digest"]:
            raise ValueError(f"cached {image} does not match BuildManifest for {profile}")
        sources[image] = source
    return fw, keys, sources


def build(kit_root, output, cache, project_root, profile="n53-12F70",
          skip_fetch=False):
    kit_root = Path(kit_root).expanduser().resolve()
    output, cache = Path(output).resolve(), Path(cache).resolve()
    project_root = Path(project_root).resolve()

    if skip_fetch:
        fw, keys, sources = cached_components(cache, profile)
    else:
        cache.mkdir(parents=True, exist_ok=True)
        progress(f"fetching {profile} firmware components")
        fetch_components(kit_root, cache, profile)
        fw, keys, sources = cached_components(cache, profile)
    output.mkdir(parents=True, exist_ok=True)
    img4 = kit_bin(kit_root, "img4")
    hfsplus = kit_bin(kit_root, "hfsplus")

    dec = cache / "decrypted"; dec.mkdir(exist_ok=True)
    ibss_dec, ibec_dec = dec / "iBSS.raw", dec / "iBEC.raw"
    kernel_dec, dt_dec = dec / "Kernelcache.dec", dec / "DeviceTree.raw"
    rd = dec / "RestoreRamdisk.dmg"
    progress("decrypting iBSS")
    decrypt_img4(img4, sources["iBSS"], ibss_dec,
                 key_for(keys, "iBSS", sources["iBSS"].name))
    progress("decrypting iBEC")
    decrypt_img4(img4, sources["iBEC"], ibec_dec,
                 key_for(keys, "iBEC", sources["iBEC"].name))
    progress("decrypting kernelcache")
    decrypt_img4(img4, sources["Kernelcache"], kernel_dec,
                 key_for(keys, "Kernelcache", sources["Kernelcache"].name),
                 decompress=True)
    progress("decrypting DeviceTree")
    decrypt_img4(img4, sources["DeviceTree"], dt_dec,
                 key_for(keys, "DeviceTree", sources["DeviceTree"].name))
    progress("decrypting restore ramdisk")
    decrypt_img4(img4, sources["RestoreRamdisk"], rd,
                 key_for(keys, "RestoreRamdisk", sources["RestoreRamdisk"].name))

    patched = output / "raw"; patched.mkdir(exist_ok=True)
    ibss_raw, ibec_raw = patched / "iBSS.raw", patched / "iBEC.raw"
    kernel_raw = patched / "Kernelcache.comp"
    ios9 = get_profile(profile)["version"].startswith("9.")
    if ios9:
        progress("pattern-patching iOS 9 iBSS and iBEC")
        patch_ios9_stage(ibss_dec, ibss_raw, "iBSS", output / "iBSS.patch.json")
        patch_ios9_stage(ibec_dec, ibec_raw, "iBEC", output / "iBEC.patch.json")
        progress("preparing the stock iOS 9 kernel and monitor")
        pack_stock_kernel(kernel_dec, kernel_raw, output / "Kernel.patch.json")
    else:
        progress("pattern-patching iBSS, iBEC, and kernelcache")
        patch_ibss(ibss_dec, ibss_raw, profile, output / "iBSS.patch.json")
        patch_ibec(ibec_dec, ibec_raw, profile, output / "iBEC.patch.json")
        patch_kernel(kernel_dec, kernel_raw, profile, output / "Kernel.patch.json")

    ramdisk = output / "ramdisk.dmg"
    progress("creating the SSH ramdisk filesystem")
    ios7 = get_profile(profile)["version"].startswith("7.")
    ios7_restored = dec / "ios7-restored_external"
    ios7_launchctl = dec / "ios7-launchctl"
    if ios7:
        hfs(hfsplus, rd, "extract", "usr/local/bin/restored_external",
            ios7_restored)
        hfs(hfsplus, rd, "extract", "bin/launchctl", ios7_launchctl)
    shutil.copy2(rd, ramdisk)
    if ios9:
        # This hfsplus build cannot jump from 31 MB to 210 MB in one grow.
        hfs(hfsplus, ramdisk, "grow", "133169152")
        hfs(hfsplus, ramdisk, "grow", "210000000")
    else:
        hfs(hfsplus, ramdisk, "grow", "50000000")
    hfs(hfsplus, ramdisk, "untar", ensure_iram(kit_root, cache,
                                               allow_download=not skip_fetch))
    hfs(hfsplus, ramdisk, "untar", kit_root / "resources/sshrd/sbplist.tar")
    if ios7:
        # iram carries a newer launchctl and restored_external.  Both happened
        # to run on iOS 8, but their deployment targets and private-framework
        # imports are unsafe on 7.1.  Restore the matching Apple binaries from
        # the source ramdisk before installing our small shell entry point.
        for source, target, mode in [
            (ios7_launchctl, "bin/launchctl", "755"),
            (ios7_restored, "usr/local/bin/restored_external", "755"),
        ]:
            hfs(hfsplus, ramdisk, "rm", target)
            hfs(hfsplus, ramdisk, "add", source, target)
            hfs(hfsplus, ramdisk, "chmod", mode, target)
            hfs(hfsplus, ramdisk, "chown", "0:0", target)
        # iram also includes its previous Dropbear build, whose Mach-O
        # deployment target is iOS 7.0.  The default build targets iOS 9.
        ios7_dropbear = dec / "ios7-dropbear"
        if ios7_dropbear.exists():
            ios7_dropbear.unlink()
        hfs(hfsplus, ramdisk, "extract", "usr/local/bin/dropbear.orig",
            ios7_dropbear)
        hfs(hfsplus, ramdisk, "rm", "usr/local/bin/dropbear")
        hfs(hfsplus, ramdisk, "mv", "usr/local/bin/dropbear.orig",
            "usr/local/bin/dropbear")
    # iOS 9 needs the native SSHRD USB helper as launchd's executable entry.
    # Its tested shell and launchctl also match the 13E238 restore userland.
    ios9_userland = kit_root / "resources/ios9-sshrd"
    if ios9:
        # The older iRam utilities can be rejected on iOS 9.0.x; preserve the
        # matching restore image's small filesystem commands for mount setup.
        for name in ("mkdir", "rm"):
            native = dec / ("ios9-native-" + name)
            if native.exists():
                native.unlink()
            hfs(hfsplus, rd, "extract", "bin/" + name, native)
            hfs(hfsplus, ramdisk, "rm", "bin/" + name)
            hfs(hfsplus, ramdisk, "add", native, "bin/" + name)
            hfs(hfsplus, ramdisk, "chmod", "755", "bin/" + name)
            hfs(hfsplus, ramdisk, "chown", "0:0", "bin/" + name)
        for source_name, target in [("sh", "bin/sh"),
                                    ("bash", "bin/bash"),
                                    ("launchctl", "bin/launchctl"),
                                    ("dropbear", "usr/local/bin/dropbear"),
                                    ("restored_external", "usr/local/bin/restored_external")]:
            source = ios9_userland / source_name
            if not source.is_file():
                raise FileNotFoundError(f"missing tested iOS 9 userland: {source}")
            hfs(hfsplus, ramdisk, "rm", target)
            hfs(hfsplus, ramdisk, "add", source, target)
            hfs(hfsplus, ramdisk, "chmod", "755", target)
            hfs(hfsplus, ramdisk, "chown", "0:0", target)
        compatible_shell = ios9_userland / "sh"
    else:
        # iRam's default /bin/sh needs ncurses 5.4; iOS 7/8 provide 5.0.
        compatible_shell = dec / "compatible-sh"
        if compatible_shell.exists():
            compatible_shell.unlink()
        hfs(hfsplus, ramdisk, "extract", "bin/bash", compatible_shell)
        hfs(hfsplus, ramdisk, "rm", "bin/sh")
        hfs(hfsplus, ramdisk, "add", compatible_shell, "bin/sh")
        hfs(hfsplus, ramdisk, "chmod", "755", "bin/sh")
        hfs(hfsplus, ramdisk, "chown", "0:0", "bin/sh")
    assets = project_root / "ramdisk"
    hfs(hfsplus, ramdisk, "mkdir", "private/var/mobile")
    hfs(hfsplus, ramdisk, "chown", "501:501", "private/var/mobile")
    for existing in ("private/etc/master.passwd", "private/etc/motd"):
        hfs(hfsplus, ramdisk, "rm", existing)
    # The iOS 7 restore ramdisk has no LaunchDaemons directory.  hfsplus
    # otherwise reports the missing parent on stdout but exits successfully.
    hfs(hfsplus, ramdisk, "mkdir", "System/Library/LaunchDaemons")
    if not ios7 and not ios9:
        keybagd_plist = assets / "com.apple.mobile.keybagd.plist"
        hfs(hfsplus, ramdisk, "add", keybagd_plist,
            "System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist")
        hfs(hfsplus, ramdisk, "chmod", "644",
            "System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist")
        hfs(hfsplus, ramdisk, "chown", "0:0",
            "System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist")
    if ios9:
        profile_marker = output / "ios9-profile.txt"
        profile_marker.write_text(profile + "\n")
        for source, target in [
            (assets / "com.apple.mobile.keybagd-ios9.plist",
             "private/var/tmp/com.apple.mobile.keybagd-ios9.plist"),
            (profile_marker, "private/var/tmp/ios9-profile.txt"),
        ]:
            hfs(hfsplus, ramdisk, "add", source, target)
            hfs(hfsplus, ramdisk, "chmod", "644", target)
            hfs(hfsplus, ramdisk, "chown", "0:0", target)
        hfs(hfsplus, ramdisk, "symlink",
            "private/var/keybags", "/mnt2/keybags")
    for source, target, mode in [
        (assets / "master.passwd", "private/etc/master.passwd", "600"),
        (assets / "motd", "private/etc/motd", "644"),
    ]:
        hfs(hfsplus, ramdisk, "add", source, target)
        hfs(hfsplus, ramdisk, "chmod", mode, target)
        hfs(hfsplus, ramdisk, "chown", "0:0", target)
    if not ios9:
        hfs(hfsplus, ramdisk, "mv", "usr/local/bin/restored_external",
            "usr/local/bin/ramdisk-usb-start")
    for source, target in ([
        (assets / "mount-mnt2", "usr/local/bin/mount-mnt2")]
        + ([] if ios9 else [
            (assets / "entry.sh", "usr/local/bin/restored_external")])):
        hfs(hfsplus, ramdisk, "add", source, target)
        hfs(hfsplus, ramdisk, "chmod", "755", target)
        hfs(hfsplus, ramdisk, "chown", "0:0", target)

    if ios7:
        # The installed system volume supplies its exact matching daemon at
        # mount time.  This tool patches the copy into writable /mnt2/tmp.
        keybagd_patcher = assets / "patch-keybagd"
        if not keybagd_patcher.is_file():
            raise FileNotFoundError(f"missing iOS 7 patcher: {keybagd_patcher}")
        hfs(hfsplus, ramdisk, "mkdir", "usr/local/libexec")
        hfs(hfsplus, ramdisk, "add", keybagd_patcher,
            "usr/local/libexec/patch-keybagd")
        hfs(hfsplus, ramdisk, "chmod", "755",
            "usr/local/libexec/patch-keybagd")
        hfs(hfsplus, ramdisk, "chown", "0:0",
            "usr/local/libexec/patch-keybagd")
    if ios9:
        patcher = assets / "patch-keybagd-ios9"
        if not patcher.is_file():
            raise FileNotFoundError(f"missing iOS 9 keybagd patcher: {patcher}")
        hfs(hfsplus, ramdisk, "mkdir", "usr/local/libexec")
        hfs(hfsplus, ramdisk, "add", patcher,
            "usr/local/libexec/patch-keybagd-ios9")
        hfs(hfsplus, ramdisk, "chmod", "755",
            "usr/local/libexec/patch-keybagd-ios9")
        hfs(hfsplus, ramdisk, "chown", "0:0",
            "usr/local/libexec/patch-keybagd-ios9")
        hfs(hfsplus, ramdisk, "add", assets / "mount-ios9-stage",
            "usr/local/bin/mount-ios9-stage")
        hfs(hfsplus, ramdisk, "chmod", "755", "usr/local/bin/mount-ios9-stage")
        hfs(hfsplus, ramdisk, "chown", "0:0", "usr/local/bin/mount-ios9-stage")
        hfs(hfsplus, ramdisk, "add", assets / "finish-ios9-keybagd",
            "usr/local/bin/finish-ios9-keybagd")
        hfs(hfsplus, ramdisk, "chmod", "755", "usr/local/bin/finish-ios9-keybagd")
        hfs(hfsplus, ramdisk, "chown", "0:0", "usr/local/bin/finish-ios9-keybagd")

    for source, target, scratch_name in [
        (assets / "mount-mnt2", "usr/local/bin/mount-mnt2",
         "verify-mount-mnt2"),
    ]:
        verify_hfs_file(hfsplus, ramdisk, target, source, dec / scratch_name)
    if ios9:
        for name in ("mkdir", "rm"):
            verify_hfs_file(hfsplus, ramdisk, "bin/" + name,
                            dec / ("ios9-native-" + name),
                            dec / ("verify-ios9-native-" + name))
        for source_name, target in [("restored_external", "usr/local/bin/restored_external"),
                                    ("dropbear", "usr/local/bin/dropbear"),
                                    ("bash", "bin/bash"),
                                    ("launchctl", "bin/launchctl")]:
            verify_hfs_file(hfsplus, ramdisk, target,
                            ios9_userland / source_name,
                            dec / ("verify-ios9-" + source_name))
    else:
        verify_hfs_file(hfsplus, ramdisk, "usr/local/bin/restored_external",
                        assets / "entry.sh", dec / "verify-entry.sh")
    if ios7:
        verify_hfs_file(hfsplus, ramdisk, "usr/local/bin/dropbear",
                        ios7_dropbear, dec / "verify-ios7-dropbear")
        verify_hfs_file(hfsplus, ramdisk, "usr/local/libexec/patch-keybagd",
                        keybagd_patcher, dec / "verify-ios7-keybagd-patcher")
    elif not ios9:
        verify_hfs_file(
            hfsplus, ramdisk,
            "System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist",
            assets / "com.apple.mobile.keybagd.plist",
            dec / "verify-ios8-keybagd-plist")
    else:
        for target, source in [
            ("usr/local/libexec/patch-keybagd-ios9", assets / "patch-keybagd-ios9"),
            ("usr/local/bin/mount-ios9-stage", assets / "mount-ios9-stage"),
            ("usr/local/bin/finish-ios9-keybagd", assets / "finish-ios9-keybagd"),
            ("private/var/tmp/com.apple.mobile.keybagd-ios9.plist",
             assets / "com.apple.mobile.keybagd-ios9.plist"),
            ("private/var/tmp/ios9-profile.txt", profile_marker),
        ]:
            verify_hfs_file(hfsplus, ramdisk, target, source,
                            dec / ("verify-" + Path(target).name))
    verify_hfs_file(hfsplus, ramdisk, "bin/sh", compatible_shell,
                    dec / "verify-compatible-sh")

    ticket = kit_root / f"resources/sshrd/IM4M{get_profile(profile)['ticket']}"
    artifacts = {
        "iBSS.im4p": (ibss_raw, "ibss"),
        "iBEC.im4p": (ibec_raw, "ibec"),
        "Kernelcache.img4": (kernel_raw, "rkrn"),
        "DeviceTree.img4": (dt_dec, "rdtr"),
        "RestoreRamdisk.img4": (ramdisk, "rdsk"),
    }
    for name, (source, typ) in artifacts.items():
        progress(f"creating {name}")
        if ios9 and name == "Kernelcache.img4":
            # The stock IM4P includes an appended monitor segment. Rebuilding
            # it from only complzss drops that segment and prevents boot.
            run([img4, "-i", source, "-o", output / name, "-M", ticket])
        else:
            wrap(img4, ticket, source, output / name, typ)
    manifest = {
        "profile": profile, "firmware": fw,
        "key_source": "Legacy-iOS-Kit-Keys af6bf5934dc61ed557a967a3f42ab7fb8ed8c45e",
        "artifacts": {name: sha256(output / name) for name in artifacts},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    progress(f"created {profile} ramdisk artifacts")
    return manifest
