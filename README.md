# QwQramdisk

QwQramdisk builds and boots an iOS 7/8 arm64 SSH ramdisk for the global
iPhone 5s (`iPhone6,2`, `n53ap`) and mounts the protected data volume at
`/mnt2` read-write.

The tool accepts the installed iOS version, detects the connected DFU device,
downloads only the required IPSW members, discovers patch locations from
ARM64 patterns and cross-references, and produces bootable IMG4 components.
It does not download the full IPSW or RootFS.

Physical-device validation is complete for:

| Device | iOS | Build | SSH | SEP | systembag | `/mnt2` R/W |
|---|---:|---:|---:|---:|---:|---:|
| iPhone6,2 | 7.1.1 | 11D201 | PASS | PASS | PASS | PASS |
| iPhone6,2 | 8.3 | 12F70 | PASS | PASS | PASS | PASS |

Binary pattern regression also covers 7.0.6, 7.1, 7.1.2, 8.0, 8.1, 8.2,
and 8.4.1. Those versions have not all been validated on physical devices.

## Requirements

- macOS or Linux with Python 3
- a C compiler for the fast LZSS encoder
- [Legacy-iOS-Kit](https://github.com/LukeZGD/Legacy-iOS-Kit) at
  `~/Legacy-iOS-kit`, or a custom path passed with `--kit`
- an iPhone6,2 in DFU mode
- USB access; a serial cable is optional

On Apple Silicon macOS, QwQramdisk uses Legacy-iOS-Kit's packaged `pzb`,
`img4`, `hfsplus`, `irecovery`, `ipwnder`, `gaster`, `iproxy`, and `sshpass`.

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

## Commands

```text
doctor          Check required Legacy-iOS-Kit tools
versions        List firmware profiles and physical-test status
fetch           Download only the required IPSW members
create          Build patched IMG4 components and the SSH ramdisk
boot            Exploit DFU, send the components, and start USB/SSH forwarding
mount           Run the verified /mnt2 mount workflow over SSH
ssh             Open an interactive root shell
patch-ibss      Pattern-patch a decrypted iBSS
patch-ibec      Pattern-patch a decrypted iBEC
patch-kernel    Pattern-patch a decrypted kernelcache
```

`create` and `boot` read PRODUCT and MODEL from `irecovery`. The user supplies
only the installed iOS version. An explicit internal profile may still be used
for regression and development.

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

It locates serial diagnostics from the `debug` and `serial` boot-argument XREFs
instead of fixed offsets. The storage patches then split by OS generation:

- iOS 8 permits the required 0x7D0 UID AES path and forces the existing
  `ART_NO_ART` arm in `AppleSEPARTStorage::handle_first_connected()`. Loading a
  restore ART here caused SEPART stalls or panics.
- iOS 7 keeps the native persisted `ART_LOAD` decision. Forcing `ART_NO_ART`
  allowed SEP to ping but left the device data volume unreadable with HFS
  error 83. The iOS 7 path instead trusts SecureRoot and permits the diagnostic
  UID/derived handles through the user-client descriptor wrapper.

### LwVM and the iOS 7 UID-mask failure

The included diagnostic reads the effaceable LwVM locker and decrypts it with
the kernel's derived 0x89B handle. Before the UID-mask fix, the device produced
an incorrect 0x89B key and a plaintext UUID that did not match the media UUID.
After the patch, the UUIDs matched byte-for-byte and `/mnt2` mounted normally.

### keybagd

Apple's keybagd uses the fixed 12-byte path `/private/var`. QwQramdisk replaces
it with the equal-length `/mnt2//././.`; VFS normalizes the redundant `/./`
components without changing the Mach-O size.

iOS 8 can mount the data volume before keybagd is started. `mount-mnt2` copies
the exact matching daemon from `/mnt1/usr/libexec/keybagd`, verifies every path
replacement, and starts the temporary copy through a launchd MachServices job.

iOS 7 has a circular dependency: copying keybagd onto `/mnt2` may itself wait
for the system keybag. The matching daemon is therefore pattern-patched during
the build and embedded on md0. A second patch forces the data-volume
`kb_load/kb_set` path even when the restore ramdisk has already installed a
system handle. The load runs before keybagd initializes its bootstrap server,
so the daemon may be started directly after `/mnt2` is attached.

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

Run the local regression set with:

```sh
python3 tests/regression.py cache/regression
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Project status

- Supported device profile: iPhone6,2 / n53ap
- Physical `/mnt2` R/W validation: iOS 7.1.1 and iOS 8.3
- Pattern regression: four iOS 7 builds and five iOS 8 builds
- Other devices require their own firmware profile, unique-pattern validation,
  and physical data-volume testing before they can be marked supported

See [VALIDATION.md](VALIDATION.md) for artifact hashes and captured acceptance
results.

## Credits

- [exploit3dguy / iArchive](https://iarchive.app) — the original iOS 8
  64-bit ramdisk method and the iRam archive/userland on which this project is
  based.
- [Legacy-iOS-Kit](https://github.com/LukeZGD/Legacy-iOS-Kit) by LukeZGD —
  firmware selection, packaged device utilities, iRam integration, IMG4/HFS
  tooling, and the established SSH ramdisk workflow.
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
- checkm8, ipwnder, gaster, libirecovery, img4lib/img4tool, hfsplus, Dropbear,
  and every upstream project distributed or invoked by Legacy-iOS-Kit.

QwQramdisk's original code covers the cross-version pattern patchers, the
iOS 7 UID/SecureRoot/ART corrections, keybagd system-handle replacement, the
unified build/boot interface, and the verified `/mnt2` acceptance workflow.

## License

Original QwQramdisk source code is released under the [MIT License](LICENSE).
Third-party tools, binaries, and firmware components remain subject to their
respective licenses and terms.
