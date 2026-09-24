# QwQramdisk

> **Linux support is experimental.** The complete workflow is implemented for
> x86_64 and arm64 Linux hosts, but DFU exploitation and USB re-enumeration have
> not yet received the same physical-device coverage as macOS. Keep a macOS host
> available when working with irreplaceable device data.

QwQramdisk builds and boots iOS 7/8 arm64 SSH ramdisks for the iPhone 5s,
iPhone 6, iPhone 6 Plus, iPad Air, and iPad Air 2 families and mounts the
protected data volume at `/mnt2` read-write.

The tool accepts the installed iOS version, detects the connected DFU device,
downloads only the required IPSW members, discovers patch locations from
ARM64 patterns and cross-references, and produces bootable IMG4 components.
It does not download the full IPSW or RootFS.

Device-tested on the iPhone 5s (iOS 7–8), iPhone 6 (iOS 8), and
iPad mini 2 (iOS 7). It is expected to work on any iDevice that can run
iOS 7–8.

There is no PRODUCT/MODEL allowlist. When a connected iOS 7/8 arm64 device
has no built-in profile, QwQramdisk resolves its IPSW from the detected
PRODUCT, MODEL, CPID, and BDID and creates an experimental profile at
runtime. This opens the workflow to every A7, A8, and A8X model, including
the iPad mini 2/3 and iPod touch 6. Pattern matching still fails closed if
that firmware has an unknown or ambiguous layout.

## Requirements

- Intel/Apple Silicon macOS, or x86_64/arm64 Linux, with Python 3
- a C compiler is optional (it accelerates LZSS compression)
- an identified device in DFU mode
- USB access; a serial cable is optional

The repository includes native x86_64 and arm64 copies of every macOS and Linux
host tool and all ramdisk resources used by the workflow. The correct binary
set is selected from the operating system and architecture, so Rosetta or a
separate Legacy-iOS-Kit checkout is not required. Unsupported operating systems
and CPU architectures fail closed instead of trying an incompatible binary.

On Debian/Ubuntu Linux, install Python and the OpenSSH client:

```sh
sudo apt install python3 openssh-client
```

## Quick start

```sh
git clone https://github.com/j1ans/QwQramdisk.git
cd QwQramdisk
chmod +x qwqramdisk

./qwqramdisk doctor
./qwqramdisk versions
./qwqramdisk create 8.3
./qwqramdisk boot 8.3
./qwqramdisk mount
./qwqramdisk ssh
```

The SSH endpoint is `root@localhost:2236`, password `alpine`.

For iOS 7.1.1, use the same commands with `7.1.1`:

```sh
./qwqramdisk create 7.1.1
./qwqramdisk boot 7.1.1
./qwqramdisk mount
```

`mount` leaves `/mnt2` mounted. Before reporting success, the device-side
helper reads the existing system keybag and performs a create, read, compare,
and delete probe under `/mnt2/tmp`.

## Dump and restore activation records

```sh
./qwqramdisk boot 7.1.1 --dump-activation        # boot, then dump in one run
./qwqramdisk dump-activation                     # ramdisk already booted
./qwqramdisk restore-activation activation-7.1.1-11D201.tar
```

The dump is simply the device's activation folder — activation record,
`data_ark.plist`, device keys, escrow and pair records — packaged as a
`Lockdown/` tree with the real on-device modes and ownership
(`activation-<version>-<build>.tar`, by default under `output/<profile>/`
for `boot` and in the current directory for `dump-activation`).

`restore-activation` writes the folder back to
`/mnt2/root/Library/Lockdown`, copying the live folder to
`Lockdown.bak-<timestamp>` on the device first. Every restored file is
size-checked against the tar before the command reports success.

iOS 7 records are read from `/mnt2/root/Library/Lockdown` and iOS 8 records
from `/mnt2/mobile/Library/mad`, both packaged under the `Lockdown/` name;
the location suggested by the installed version is preferred and the other
is used as a fallback when it is the one holding a `*_record.plist`. A dump
or restore without any `*_record.plist` fails with an unactivated-device
hint instead of moving a useless tree around.

The iRam userland in the ramdisk is linked against iOS 9+ libSystem symbols,
so its `tar` and `ls -l` crash on the iOS 7 restore ramdisk. Nothing is
therefore archived on the device: `find -ls` provides the listing, `scp`
moves the files, and the tar is assembled and verified on the host.

## Arm or clear the springboard device lock

```sh
./qwqramdisk lock-wipe                          # arm the wipe path
./qwqramdisk remove-disabled                    # clear the disabled state
```

Both edit `/mnt2/mobile/Library/Preferences/com.apple.springboard.plist` on
the host (pull, mutate with plistlib, push back with the original 0600
mobile:mobile mode, keeping an on-device `.bak-<timestamp>` copy) and
re-read the pushed file to verify before reporting success.

`lock-wipe` sets `SBDeviceLockFailedAttempts=721` and
`SBDeviceWipeEnabled=true`; on the next normal boot springboard sees the
failed-attempt counter far past the wipe threshold with wiping enabled.
`remove-disabled` sets the counter to `-9999`, deletes every other
`SBDevice*` key, and removes all `LockoutState*` files from
`/mnt2/mobile/Library/SpringBoard`.

## Commands

```text
doctor          Check the bundled host tools and ramdisk resources
versions        List firmware profiles and physical-test status
fetch           Download only the required IPSW members
create          Build patched IMG4 components and the SSH ramdisk
boot            Exploit DFU, send the components, and start USB/SSH forwarding
mount           Run the verified /mnt2 mount workflow over SSH
dump-activation Package the activation Lockdown folder into a tar
restore-activation Write a dumped tar back onto the device
lock-wipe       Arm the springboard wipe lock (721 attempts, wipe enabled)
remove-disabled Clear the disabled state (-9999 attempts, drop SBDevice* keys)
ssh             Open an interactive root shell
patch-ibss      Pattern-patch a decrypted iBSS
patch-ibec      Pattern-patch a decrypted iBEC
patch-kernel    Pattern-patch a decrypted kernelcache
```

`create` and `boot` read PRODUCT and MODEL from `irecovery`. The user supplies
only the installed iOS version. A known device uses its validated profile; any
other iOS 7/8 A7/A8/A8X device receives an experimental runtime profile. An
explicit internal profile may still be used for regression and development.

## How the `/mnt2` fix works

Mounting `/mnt1` despite a re-key warning does not prove that `/mnt2` can be
used. The data partition depends on the complete UID AES, SEP, LwVM,
AppleKeyStore, and keybagd chain:

```text
iBSS/iBEC UID state
        -> kernel IOAES handles
        -> matching SEP/ART state
        -> LwVM partition keybag
        -> HFS data-volume mount
        -> keybagd system/class keys
```

QwQramdisk repairs each stage and rejects an unknown or ambiguous patch site.

### iBSS and iBEC

The patchers distinguish the iOS 7 `iBoot-1940.x` family from the iOS 8
`iBoot-2261.x` family.

For iOS 8, the Image4 validation callback is found from the manifest decoder's
unique call XREF and callback ADR. iBEC additionally locates the payload
digest helper, aggregate/root-manifest result branches, debug capability,
`uid-aes-key`, and the boot-argument reference.

For iOS 7, the newer Image4 callback layout does not exist. The patcher anchors
on the BNCH property dispatcher and validates the enclosing function prologue
before replacing the real signature-check entry. This avoids returning from an
internal error block with a damaged stack.

Both generations contain a bootx UID-mask decision and an early UID-disable
call. The relevant selection differs by register:

```text
iOS 7: CSEL W1, W20, W9, NE -> MOV W1, W20
iOS 8: CSEL W1, W21, W9, NE -> MOV W1, W21
```

The iOS 7 iBEC path also publishes `system-trusted`. Without it, the restore
root is not accepted by SecureRoot and the derived 0x89B key table is wrong,
even when `/chosen/uid-aes-key` is present.

### Kernel, IOAES, and ART

The kernel patcher works on raw arm64 Mach-O files or `complzss` payloads and
preserves the appended monitor data when repacking.

It locates the serial configuration from the `debug` and `serial` boot-argument XREFs
instead of fixed offsets. The storage patches then split by OS generation:

- iOS 8 permits the required 0x7D0 UID AES path and forces the existing
  `ART_NO_ART` arm in `AppleSEPARTStorage::handle_first_connected()`. Loading a
  restore ART here caused SEPART stalls or panics.
- iOS 7 keeps the native persisted `ART_LOAD` decision. Forcing `ART_NO_ART`
  allowed SEP to ping but left the device data volume unreadable with HFS
  error 83. The iOS 7 path instead trusts SecureRoot and permits the required
  UID/derived handles through the user-client descriptor wrapper.

### keybagd

Apple's keybagd uses the fixed 12-byte path `/private/var`. QwQramdisk replaces
it with the equal-length `/mnt2//././.`; VFS normalizes the redundant `/./`
components without changing the Mach-O size.

iOS 8 can mount the data volume before keybagd is started. `mount-mnt2` copies
the exact matching daemon from `/mnt1/usr/libexec/keybagd`, verifies every path
replacement, and starts the temporary copy through a launchd MachServices job.

For iOS 7, `mount-mnt2` first attaches `/mnt1`, mounts `/mnt2` with HFS
journaling enabled, then loads the matching SEP firmware. It reads the exact
matching daemon from `/mnt1/usr/libexec/keybagd` and patches a copy into
`/mnt2/tmp`, as on iOS 8.
The iOS 7 patch also forces the data-volume `kb_load/kb_set` path even when the
restore ramdisk has already installed a system handle. The daemon starts after
the patch. Building iOS 7.1.2 no longer needs a separately supplied
`keybagd.11D257.raw`.

### Compatible SSH userland

The build uses the iRam userland, then applies version-specific fixes:

- iOS 7 restores the matching Apple USB helper and `launchctl` from the source
  restore ramdisk and selects iRam's iOS-7-compatible Dropbear.
- On iOS 7 and iOS 8, iRam's compatible `bash` is installed at `/bin/sh`.
  The newer default shell requires ncurses compatibility 5.4, while these
  restore ramdisks provide 5.0.
- Root and mobile use `/bin/sh`; `/private/var/mobile` is created with uid/gid
  501 so Dropbear accepts and initializes the accounts correctly.

## Pattern safety

No supported patch uses a version-specific hard-coded offset at runtime. Each
locator combines a stable byte or string anchor with ARM64 instruction
semantics, literal/call XREFs, and local control-flow validation. The patcher
stops if an anchor is absent, duplicated, points outside the expected function,
or the original instruction differs.

Patch manifests record source and output hashes, file offsets, virtual
addresses, XREFs, original bytes, and replacements.

## Project status

- Device-tested and passing on the iPhone 5s (iOS 7–8), iPhone 6 (iOS 8),
  and iPad mini 2 (iOS 7)
- macOS is device-tested; Linux x86_64/arm64 support is experimental and has
  host-tool/unit coverage but still needs broader physical-device validation
- Every other iOS 7/8 A7/A8/A8X PRODUCT/MODEL is auto-detected without a
  model allowlist and is expected to work
- `versions` prints the validation level for every selectable profile

## Credits

- [exploit3dguy / iArchive](https://iarchive.app) — the original iOS 8
  64-bit ramdisk method and the iRam archive/userland on which this project is
  based.
- [Legacy-iOS-Kit](https://github.com/LukeZGD/Legacy-iOS-Kit) by LukeZGD —
  firmware selection, packaged device utilities, iRam integration, IMG4/HFS
  tooling, the established SSH ramdisk workflow, and the bundled host-tool
  builds. The original macOS set came from commit
  `bd921d51d8d84232d668adfd54e3e1e2edff9a33`; Linux builds come from commit
  `15263963392b548d3ab56ce95c08b37265394b31`.
- [SSHRD_Script](https://github.com/verygenericname/SSHRD_Script) by Nathan /
  verygenericname — reference for modern checkm8 SSH ramdisk construction and
  boot sequencing.
- [iphone-dataprotection](https://github.com/dinosec/iphone-dataprotection) —
  reference implementation and documentation for Apple data protection,
  keybags, LwVM, and hardware AES behavior.
- [liboffsetfinder64](https://github.com/n1z19/liboffsetfinder64) by n1z19 —
  inspiration for semantic ARM64 offset discovery through patterns and XREFs.
- iPatcher and the legacy iBoot patching community — reference for the
  `iBoot-1940.x` BNCH dispatcher strategy.
- [libfragmentzip](https://github.com/tihmstar/libfragmentzip) (`pzb`),
  [img4lib](https://github.com/xerub/img4lib) (`img4`),
  [daibutsuCFW/xpwn](https://github.com/LukeZGD/daibutsuCFW) (`hfsplus`),
  [libirecovery](https://github.com/LukeeGD/libirecovery),
  [ipwnder_lite](https://github.com/LukeZGD/ipwnder_lite/tree/old),
  [gaster](https://github.com/LukeZGD/gaster),
  [libusbmuxd](https://github.com/LukeeGD/libusbmuxd) (`iproxy`),
  [sshpass](https://sourceforge.net/projects/sshpass/), checkm8, and Dropbear.

Bundled file hashes are recorded in `vendor/SHA256SUMS`; the Legacy-iOS-Kit
GPL text is retained under `vendor/licenses`. Each upstream component keeps
its own copyright and license.

QwQramdisk's original code covers the cross-version pattern patchers, the
iOS 7 UID/SecureRoot/ART corrections, keybagd system-handle replacement, the
unified build/boot interface, and the verified `/mnt2` acceptance workflow.

## License

Original QwQramdisk source code is released under the [MIT License](LICENSE).
Third-party tools, binaries, and firmware components remain subject to their
respective licenses and terms.
