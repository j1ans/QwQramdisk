import json
import shutil
import urllib.request
import zipfile
from pathlib import Path
from .common import kit_bin, run, sha256
from .fetch import fetch_components, key_for
from .patch_ibec import patch as patch_ibec
from .patch_ibss import patch as patch_ibss
from .patch_kernel import patch as patch_kernel
from .patch_keybagd import patch as patch_keybagd
from .profiles import get_profile

IRAM_URL = "https://github.com/LukeZGD/Legacy-iOS-Kit/files/14952123/iram.zip"


def ensure_iram(tools_root, cache):
    tools_root, cache = Path(tools_root), Path(cache)
    bundled = tools_root / "resources/iram.tar"
    if bundled.is_file():
        return bundled
    target = cache / "iram.tar"
    if target.is_file():
        return target
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
    run([hfsplus, image, *args])


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


def build(kit_root, output, cache, project_root, profile="n53-12F70",
          skip_fetch=False):
    kit_root = Path(kit_root).expanduser().resolve()
    output, cache = Path(output).resolve(), Path(cache).resolve()
    project_root = Path(project_root).resolve()
    output.mkdir(parents=True, exist_ok=True); cache.mkdir(parents=True, exist_ok=True)
    img4 = kit_bin(kit_root, "img4")
    hfsplus = kit_bin(kit_root, "hfsplus")

    if skip_fetch:
        fw = json.loads((cache / "firmware.json").read_text())
        keys = json.loads((cache / "keys.json").read_text())
        enc = cache / "encrypted"
        sources = {"BuildManifest": cache / "BuildManifest.plist"}
        for image in ("iBSS", "iBEC", "Kernelcache", "DeviceTree", "RestoreRamdisk"):
            sources[image] = enc / key_for(keys, image)["filename"]
    else:
        fw, keys, sources = fetch_components(kit_root, cache, profile)

    dec = cache / "decrypted"; dec.mkdir(exist_ok=True)
    ibss_dec, ibec_dec = dec / "iBSS.raw", dec / "iBEC.raw"
    kernel_dec, dt_dec = dec / "Kernelcache.dec", dec / "DeviceTree.raw"
    rd = dec / "RestoreRamdisk.dmg"
    decrypt_img4(img4, sources["iBSS"], ibss_dec, key_for(keys, "iBSS"))
    decrypt_img4(img4, sources["iBEC"], ibec_dec, key_for(keys, "iBEC"))
    decrypt_img4(img4, sources["Kernelcache"], kernel_dec,
                 key_for(keys, "Kernelcache"), decompress=True)
    decrypt_img4(img4, sources["DeviceTree"], dt_dec, key_for(keys, "DeviceTree"))
    decrypt_img4(img4, sources["RestoreRamdisk"], rd, key_for(keys, "RestoreRamdisk"))

    patched = output / "raw"; patched.mkdir(exist_ok=True)
    stale_keybagd = patched / "keybagd.mnt2"
    if stale_keybagd.exists():
        stale_keybagd.unlink()
    ibss_raw, ibec_raw = patched / "iBSS.raw", patched / "iBEC.raw"
    kernel_raw = patched / "Kernelcache.comp"
    patch_ibss(ibss_dec, ibss_raw, profile, output / "iBSS.patch.json")
    patch_ibec(ibec_dec, ibec_raw, profile, output / "iBEC.patch.json")
    patch_kernel(kernel_dec, kernel_raw, profile, output / "Kernel.patch.json")

    ramdisk = output / "ramdisk.dmg"
    ios7 = get_profile(profile)["version"].startswith("7.")
    ios7_restored = dec / "ios7-restored_external"
    ios7_launchctl = dec / "ios7-launchctl"
    if ios7:
        hfs(hfsplus, rd, "extract", "usr/local/bin/restored_external",
            ios7_restored)
        hfs(hfsplus, rd, "extract", "bin/launchctl", ios7_launchctl)
    shutil.copy2(rd, ramdisk)
    hfs(hfsplus, ramdisk, "grow", "50000000")
    hfs(hfsplus, ramdisk, "untar", ensure_iram(kit_root, cache))
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
    # iRam's default /bin/sh targets iOS 9.2 and requires ncurses 5.4, while
    # both tested restore ramdisks provide compatibility version 5.0.  Its
    # /bin/bash is a separate compatible build with no ncurses dependency.
    # Install that binary at Dropbear's allowed /bin/sh path on iOS 7 and 8.
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
    if not ios7:
        keybagd_plist = assets / "com.apple.mobile.keybagd.plist"
        hfs(hfsplus, ramdisk, "add", keybagd_plist,
            "System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist")
        hfs(hfsplus, ramdisk, "chmod", "644",
            "System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist")
        hfs(hfsplus, ramdisk, "chown", "0:0",
            "System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist")
    for source, target, mode in [
        (assets / "master.passwd", "private/etc/master.passwd", "600"),
        (assets / "motd", "private/etc/motd", "644"),
    ]:
        hfs(hfsplus, ramdisk, "add", source, target)
        hfs(hfsplus, ramdisk, "chmod", mode, target)
        hfs(hfsplus, ramdisk, "chown", "0:0", target)
    hfs(hfsplus, ramdisk, "mv", "usr/local/bin/restored_external",
        "usr/local/bin/ramdisk-usb-start")
    for source, target in [
        (assets / "entry.sh", "usr/local/bin/restored_external"),
        (assets / "mount-mnt2", "usr/local/bin/mount-mnt2"),
    ]:
        hfs(hfsplus, ramdisk, "add", source, target)
        hfs(hfsplus, ramdisk, "chmod", "755", target)
        hfs(hfsplus, ramdisk, "chown", "0:0", target)

    if ios7:
        # iOS 7 cannot create the usual patched keybagd copy on /mnt2 until
        # its system keybag is registered.  Keep the matching, path-relocated
        # daemon on md0 instead.  mount-mnt2 starts it after attaching the
        # data volume; the binary patch forces the data-volume system bag to
        # replace the restore ramdisk's already-present system handle.
        # iPhone6,1 and iPhone6,2 share the same system keybagd for a given
        # iOS build.  Name the embedded copy by build rather than board.
        ios7_keybagd_source = (
            assets / f"keybagd.{get_profile(profile)['build']}.raw")
        ios7_keybagd = dec / "keybagd.mnt2"
        if not ios7_keybagd_source.is_file():
            raise FileNotFoundError(
                f"missing matching iOS 7 keybagd: {ios7_keybagd_source}")
        patch_keybagd(ios7_keybagd_source, ios7_keybagd,
                      output / "keybagd.patch.json")
        hfs(hfsplus, ramdisk, "mkdir", "usr/local/libexec")
        for source, target in [
            (ios7_keybagd, "usr/local/libexec/keybagd.mnt2"),
        ]:
            hfs(hfsplus, ramdisk, "add", source, target)
            hfs(hfsplus, ramdisk, "chmod", "755", target)
            hfs(hfsplus, ramdisk, "chown", "0:0", target)

    for source, target, scratch_name in [
        (assets / "entry.sh", "usr/local/bin/restored_external",
         "verify-entry.sh"),
        (assets / "mount-mnt2", "usr/local/bin/mount-mnt2",
         "verify-mount-mnt2"),
    ]:
        verify_hfs_file(hfsplus, ramdisk, target, source, dec / scratch_name)
    if ios7:
        verify_hfs_file(hfsplus, ramdisk, "usr/local/bin/dropbear",
                        ios7_dropbear, dec / "verify-ios7-dropbear")
        verify_hfs_file(hfsplus, ramdisk, "usr/local/libexec/keybagd.mnt2",
                        ios7_keybagd, dec / "verify-ios7-keybagd")
    else:
        verify_hfs_file(
            hfsplus, ramdisk,
            "System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist",
            assets / "com.apple.mobile.keybagd.plist",
            dec / "verify-ios8-keybagd-plist")
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
        wrap(img4, ticket, source, output / name, typ)
    manifest = {
        "profile": profile, "firmware": fw,
        "key_source": "Legacy-iOS-Kit-Keys af6bf5934dc61ed557a967a3f42ab7fb8ed8c45e",
        "artifacts": {name: sha256(output / name) for name in artifacts},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
