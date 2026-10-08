# QwQramdisk

QwQramdisk supports iOS 7, iOS 8, and **experimental iOS 9** arm64 SSH
ramdisks. iOS 7/8 support includes the iPhone 5s, iPhone 6, iPhone 6 Plus,
iPad Air, and iPad Air 2 families. The iOS 9 profiles cover exact firmware
builds from 9.0 through 9.3.5. Those profiles passed offline firmware and
image checks; most have not been tested for DFU boot, SSH, or `/mnt2` mounting
on a device.

The tool accepts an iOS version and either detects a connected DFU device or
uses a specified board. It downloads only the required IPSW members, discovers
patch locations from ARM64 patterns and cross-references, and produces IMG4
components.
It does not download the full IPSW or RootFS.

Device-tested on the iPhone 5s (iOS 7–8), iPhone 6 (iOS 8),
iPad mini 2 (iOS 7), and iPhone 6s Plus (iOS 9.0.1 and 9.3.1).
The iOS 9.0.1 iPhone 6s Plus profile passed SSH and `/mnt2` read/write
testing; its current bundled-image boot regression is pending. Other iOS 9
profiles remain experimental and are selected only by exact product, board,
and firmware build.

## Requirements

- Intel or Apple Silicon macOS with Python 3; Linux is unsupported
- a C compiler is optional (it accelerates LZSS compression)
- an identified device in DFU mode for `boot` or device-detected builds
- USB access for device commands; a serial cable is optional

The repository includes native x86_64 and arm64 macOS host tools and ramdisk
resources. The correct binary set is selected by CPU architecture, so Rosetta
or a separate Legacy-iOS-Kit checkout is not required. Other host operating
systems and CPU architectures fail closed.

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

## Build without a connected device

Select a built-in board and iOS version to create the ramdisk without DFU:

```sh
./qwqramdisk create 9.3.1 --board n66map --offline
./qwqramdisk create 9.2.1 --board n66m --build 13D20 --offline
```

The board may be written as `n66m` or `n66map`. If a version has multiple
IPSW builds for that board, specify `--build` after checking the installed
build. `./qwqramdisk versions` lists the available board/build profiles.
`--offline` means no device is needed; these commands can still download the
required firmware members. To build with no network access, prepare a complete
`cache/<board>-<build>` first (for example with `fetch 9.3.1 --board n66map`),
then run:

```sh
./qwqramdisk create 9.3.1 --board n66map --offline --no-download
```

`--no-download` verifies the cached firmware identity and component hashes
before building. Use `--cache` and `--output` to select other directories. The
resulting IMG4 files and `manifest.json` are written to
`output/<board>-<build>` by default.

For iOS 7.1.1, use the same commands with `7.1.1`:

```sh
./qwqramdisk create 7.1.1
./qwqramdisk boot 7.1.1
./qwqramdisk mount
```

`mount` leaves `/mnt2` mounted. Before reporting success, the device-side
helper reads the existing system keybag and performs a create, read, compare,
and delete probe under `/mnt2/tmp`.

For an iOS 9 profile, use `create <installed-version>` and
`boot <installed-version>`. Versions with more than one IPSW build, such as
9.2.1 and 9.3, require `--profile BOARD-BUILD` for the verified installed
build. The same `/usr/local/bin/mount-mnt2` entry point handles `mount`.
The iOS 9 profiles use checked bootchain patterns and keep the release kernel.
The bundled keybagd patcher recognizes only the known 13A405 and 13E238
source hashes; other builds fail closed at `mount` until their matching
system binary is analyzed. `create` does not compile or sign the patcher.

## Dump and restore activation records

```sh
./qwqramdisk boot 7.1.1 --dump-activation        # boot, then dump in one run
./qwqramdisk dump-activation                     # ramdisk already booted
./qwqramdisk restore-activation activation-7.1.1-11D201.tar
```

The dump packages the device's activation files as a `Lockdown/` tree,
preserving their modes and ownership. Earlier versions can include device
keys, escrow and pair records; iOS 9.3+ includes the system container's
activation records and `data_ark.plist`. The default filename is
`<timestamp>-activation-<version>-<build>.tar`, under `output/<profile>/`
for `boot` and in the current directory for `dump-activation`.
The timestamp includes microseconds, and an existing output file is never
overwritten.

`restore-activation` backs up the live destination before writing. On iOS
9.3 and newer it restores `activation_records` to the system container and
`data_ark.plist` to that container's `Library/internal`; earlier versions
retain the Lockdown restore path. Every restored file is size-checked against
the tar before the command reports success.

iOS 7 records are read from `/mnt2/root/Library/Lockdown`; iOS 8 and
9.0–9.2 records are read from `/mnt2/mobile/Library/mad`. The location
suggested by the installed version is preferred, with the other as fallback.
For iOS 9.3 and newer, records come from the system container's
`Library/activation_records` and `data_ark.plist` from `Library/internal`.
All dumps use the `Lockdown/` tar layout. A dump or restore without any
`*_record.plist` fails before writing a replacement.

The iRam userland in the ramdisk is linked against iOS 9+ libSystem symbols,
so its `tar` and `ls -l` crash on the iOS 7 restore ramdisk. Nothing is
therefore archived on the device: `find -ls` provides the listing, `scp`
moves the files, and the tar is assembled and verified on the host.

## Arm or clear the springboard device lock

```sh
./qwqramdisk lock-wipe                          # iOS 7/8: arm the wipe path
./qwqramdisk remove-disabled                    # iOS 7/8: clear the disabled state
```

On iOS 7/8, both edit `/mnt2/mobile/Library/Preferences/com.apple.springboard.plist` on
the host (pull, mutate with plistlib, push back with the original 0600
mobile:mobile mode, keeping an on-device `.bak-<timestamp>` copy) and
re-read the pushed file to verify before reporting success.

`lock-wipe` sets `SBDeviceLockFailedAttempts=721` and
`SBDeviceWipeEnabled=true`; on the next normal boot springboard sees the
failed-attempt counter far past the wipe threshold with wiping enabled.
`remove-disabled` sets the counter to `-9999`, deletes every other
`SBDevice*` key, and removes all `LockoutState*` files from
`/mnt2/mobile/Library/SpringBoard`.

`remove-disabled` is not supported on iOS 9. To arm iOS 9+ Erase All Content
and Settings instead, run `./qwqramdisk nvram-erase --confirm` from the booted
ramdisk, then reboot normally. This writes and verifies
`oblit-inprogress=5` in NVRAM; the erase happens on the following boot.
`erase-ios9` remains an alias for existing scripts.

## Commands

```text
doctor          Check the bundled host tools and ramdisk resources
versions        List firmware profiles and support status
fetch           Download only the required IPSW members
create          Build patched IMG4 components and the SSH ramdisk
boot            Exploit DFU, send the components, and start USB/SSH forwarding
mount           Run the verified /mnt2 mount workflow over SSH
dump-activation Package the activation Lockdown folder into a tar
restore-activation Write a dumped tar back onto the device
lock-wipe       iOS 7/8: arm the springboard wipe lock
remove-disabled iOS 7/8: clear the disabled state
nvram-erase     Arm iOS 9+ Erase All Content and Settings in NVRAM
ssh             Open an interactive root shell
patch-ibss      Pattern-patch a decrypted iBSS
patch-ibec      Pattern-patch a decrypted iBEC
patch-kernel    Pattern-patch a decrypted kernelcache
```

By default, `create` and `boot` read PRODUCT and MODEL from `irecovery`; the
user supplies the installed iOS version. `create --board` selects a built-in
profile without a device. A known connected device uses its validated profile;
other iOS 7/8 A7/A8/A8X devices can receive a pattern-supported runtime
profile.

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

For iOS 9, `mount-mnt2` loads matching SEP firmware and mounts Data with
journaling. Its bundled arm64 patcher validates the matching
`/mnt1/usr/libexec/keybagd` by source SHA-256, relocates Data paths, checks
the output SHA-256, and changes the instructions needed to load the system
keybag while avoiding fatal NVRAM/reboot and user-session paths. The iBEC boot
arguments allow this modified system binary to start without runtime signing.
The workflow reads
the system keybag; it does not need the passcode or user files.

### Compatible SSH userland

The build uses the iRam userland, then applies version-specific fixes:

- iOS 7 restores the matching Apple USB helper and `launchctl` from the source
  restore ramdisk and selects iRam's iOS-7-compatible Dropbear.
- On iOS 7 and iOS 8, iRam's compatible `bash` is installed at `/bin/sh`.
  The newer default shell requires ncurses compatibility 5.4, while these
  restore ramdisks provide 5.0.
- Root and mobile use `/bin/sh`; `/private/var/mobile` is created with uid/gid
  501 so Dropbear accepts and initializes the accounts correctly.
- iOS 9 uses the matching restore ramdisk's `mkdir` and `rm`, avoiding newer
  iRam binaries that exit on 9.0.1.

## Pattern safety

The iOS 7/8/9 bootchain pattern patchers combine stable byte or string anchors
with ARM64 instruction semantics, call XREFs, and local control-flow checks.
They reject unknown or ambiguous layouts. The iOS 9 stock kernel retains its
monitor trailer.

Patch manifests record source and output hashes, file offsets, virtual
addresses, XREFs, original bytes, and replacements.

## Project status

- Device-tested and passing on the iPhone 5s (iOS 7–8), iPhone 6 (iOS 8),
  and iPad mini 2 (iOS 7)
- iOS 9.0–9.3.5 is experimental: 195 exact board/build combinations passed
  offline bootchain and full-image checks; most device startup and `/mnt2`
  mount combinations remain untested
- macOS x86_64 and arm64 are the supported host platforms
- iOS 7/8 A7/A8/A8X PRODUCT/MODEL combinations are available through
  automatic firmware selection without a model allowlist
- `versions` prints support status for every selectable profile

## Credits

- [exploit3dguy / iArchive](https://iarchive.app) — the original iOS 8
  64-bit ramdisk method and the iRam archive/userland on which this project is
  based.
- [Legacy-iOS-Kit](https://github.com/LukeZGD/Legacy-iOS-Kit) by LukeZGD —
  firmware selection, packaged device utilities, iRam integration, IMG4/HFS
  tooling, the established SSH ramdisk workflow, and the bundled host-tool
  builds. The original macOS set came from commit
  `bd921d51d8d84232d668adfd54e3e1e2edff9a33`.
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
