# Validation record

## Supported and tested scope

`qwqramdisk` currently targets iPhone6,2 / n53ap / A7. Pattern regression uses
Apple components and the exact firmware keys selected by each profile.

| iOS | Build | Binary pattern regression | Physical boot | `/mnt2` read/write |
|---|---|---:|---:|---:|
| 7.0.6 | 11B651 | PASS | — | — |
| 7.1 | 11D167 | PASS | — | — |
| 7.1.1 | 11D201 | PASS | PASS | PASS |
| 7.1.2 | 11D257 | PASS | — | — |
| 8.0 | 12A365 | PASS | — | — |
| 8.1 | 12B411 | PASS | — | — |
| 8.2 | 12D508 | PASS | — | — |
| 8.3 | 12F70 | PASS | PASS | PASS |
| 8.4.1 | 12H321 | PASS | — | — |

The regression gate validates unique pattern/XREF discovery and the original
instruction at every patch site. It does not substitute for a device run on
the rows marked `—`.

## Current merged artifacts

Both verified profiles were rebuilt from the current `qwqramdisk` tree using
their complete local component caches. Every hash below is recorded in and
rechecked against the corresponding `output/<profile>/manifest.json`.

### iOS 7.1.1 / n53-11D201

| Artifact | SHA-256 |
|---|---|
| `iBSS.im4p` | `10022d6e40eda5170f86c4fed58ba3e17c3edb39a1d03d332ab7d8632cfd4051` |
| `iBEC.im4p` | `f5cc3b950755e28413da8021261385ba689d5294ca6e37fc2c1172ae6fc0e790` |
| `Kernelcache.img4` | `112f747e000fb3239486fd4b0cf42147c13f395ab89987453101ea30f79062be` |
| `DeviceTree.img4` | `2b40b9a99567cb91cb9e17108bade3128ec35c6952fbed7e6fe9c4b636c92db1` |
| `RestoreRamdisk.img4` | `e8cc13e7f605f89b7eacff2a41f1a57afd1b6fc4388c1bf0d58d70b9eb71557c` |

### iOS 8.3 / n53-12F70

| Artifact | SHA-256 |
|---|---|
| `iBSS.im4p` | `021778e186a6d466360647b236ea0d9e6ebf51db171707d6d60a0e131cc75343` |
| `iBEC.im4p` | `98636f53defea21272598a6172aa6ea0fbd185a682e8e9e860add0a4fb8e173c` |
| `Kernelcache.img4` | `0c74d1dbf1352676fd6d9df999e0904692a554fbae842e070b9dd8e0d9307a4f` |
| `DeviceTree.img4` | `518a5c990a62c7b10083d9f639e25e47bdbc1c50534e347a59d3298fef66a904` |
| `RestoreRamdisk.img4` | `82472a423b65ffc8059340462497076e4b7dec4a0cba39daf21a575be5d8a061` |

## Ramdisk merge inspection

The rebuilt HFS images were reopened and compared byte-for-byte with the
current source assets.

- Both images contain the same current `usr/local/bin/mount-mnt2`.
- The iOS 7 image contains `usr/local/libexec/keybagd.mnt2`, identical to the
  output of `patch_keybagd.py`, and has no mobile-keybagd launchd job.
- The iOS 8 image contains the current
  `System/Library/LaunchDaemons/com.apple.mobile.keybagd.plist`, whose program
  is `/mnt2/tmp/qwqramdisk-keybagd`, and has no embedded patched keybagd.
- All ten generated IMG4 files match their manifest hashes.

This proves that the merged builder selects the intended version-specific
keybagd strategy rather than mixing the two implementations.

## Physical iOS 7.1.1 evidence

The final iPhone6,2 run used the corrected bootx UID-mask patch. The diagnostic
reported key 0x89B as
`98f80c7aa7f64c91152f6da317482811` and decrypted LwVM UUID
`88514f46004445a9b8579a1f67875502`, matching the media UUID. After loading the
matching SEP firmware, `mount-mnt2` printed:

```text
[mount-mnt2] system keybag read and data-volume write/read/delete passed
[mount-mnt2] ready
/dev/disk0s1s2 on /mnt2 (hfs, local, journaled, noatime, protect)
```

Evidence:

- `evidence/ios7/uid-mask-keydiag.txt`
- `evidence/ios7/mnt2-rw-validation.txt`
- `evidence/ios7/final-serial.log`

The volume was intentionally left mounted after acceptance.

## Physical iOS 8.3 evidence

The final iPhone6,2 run loaded matching 12F70 SEPI through the patched
`ART_NO_ART` flow, mounted `/mnt2`, registered the runtime-relocated matching
keybagd, read an existing protected file, and completed create/read/compare/
delete with zero return codes.

The merged `qwqramdisk` image was revalidated after installing iRam's
ncurses-independent `bash` binary at `/bin/sh`. Password SSH, the exact
`rd=md0 -v serial=3 amfi=0xff cs_enforcement_disable=1` boot arguments,
systembag read, keybagd PID/Mach services, and a second independent data-volume
write/read/delete probe all passed on 12F70. `/mnt2` was left mounted.

Evidence:

- `evidence/ios8/mnt2-rw-validation.txt`
- `evidence/ios8/runtime-keybagd.txt`
- `evidence/ios8/final-live-state.txt`
- `evidence/ios8/qwqramdisk-12F70-mnt2-rw.txt`
- `evidence/ios8/qwqramdisk-12F70-final-state.txt`

The validation recorded keybagd with active Mach and XPC endpoints and left
the data volume mounted.
