# VT, firmware and SNMP data installation (2026-11-05)

## Native construction

The source-owned share/vt parent selects both fonts and keymaps; share/snmp
selects mibs; share/firmwares selects the original iwm leaf. These mirror the
original child traversals. Their eventual inclusion in the complete share parent
must follow that parent's MK_VT, MK_BSNMP and MK_SOURCELESS_UCODE choices. Direct
child targets do not invent alternative selection policy.

VT fonts reuse bsd_loader_font with format=font, the original converter's default
format. Each action declares its HEX/BDF input, output and source-built
execution-platform vtfontcvt, including explicit native runtime libraries.
The existing rule is reused without a new generator driver, Make subprocess or
prebuilt-font substitution. All fifteen original fonts are generated; the source
index is also installed. Keymap installation declares the original 91 files,
including INDEX.keymaps. The iwm leaf preserves nine source blobs, their original
installed names, 0644 modes and firmware-iwm package. The MIB preserves its bsnmp
package and 0444 mode. VT files retain the vt-data package and 0444 modes.
Each leaf declares its original package-owned directory without requesting
unrelated package-wide mtree directories.

## Original Make comparison

| Owner | Complete metadata records | Exact file payloads |
| --- | ---: | ---: |
| vt/fonts | 17 | 16 |
| vt/keymaps | 92 | 91 |
| snmp/mibs | 2 | 1 |
| firmwares/iwm | 10 | 9 |
| Total | 121 | 117 |

All inventories, named owners, groups, numeric modes, package tags, payload bytes
and explicit directory records match the independently staged original Make
components. Archive checking rejects extra entries and verifies types, numeric
accounts, modes and epoch-zero serialization. All fifteen generated font payloads
are byte-identical to the original outputs. The original Make recipes invoke
vtfontcvt through their recorded build environment; this check establishes output
parity, not an independent reproducible-bootstrap qualification of that original
generator. Original source bindings are rechecked; native artifacts resolve only
through passed receipts and immutable capture hashes.

## Evidence under /usr/obj/usr/src

- bazel-vt-firmware-snmp-native-r1-20261105: maintained build-bsd with sixteen
  jobs builds all four archives and the native converter. The source-settings
  test passes; it is not a console/network/hardware test.
- bazel-share-{vt-fonts,vt-keymaps,snmp-mibs,firmwares-iwm}-make-r1-20261105:
  four independent original Make build/stage references with metadata recipes.
- bazel-vt-firmware-snmp-original-review-r1-20261105/review.json: complete
  121-record/117-payload comparison; audit source and all bindings retained.
- bazel-share-extended-namespace-r1-20261105/review.json: cross-capture namespace
  reconciliation with the earlier nine-family and six shared-data captures:
  1124 unique archives, 23575 non-directory paths and zero conflicting file claims.
  This is not a combined native world build or complete directory/pkgbase parity.

## Frontend, remaining work and runtime limits

The format-5 frontend accepts these targets with its existing inputs. The manual
now describes their generation and limits; no C dispatcher/schema or signing/
publication change is necessary. No tracked Python implementation or original
application/instrumentation source changes are part of this checkpoint. Base
firmware ownership follows the original Make source; separate hardware builds and
combined repository publication requirements remain unchanged.

Live console/font/keymap behavior, SNMP operation, firmware loading and wireless
operation still require runtime qualification. Complete share selection and
remaining content (docs/examples, manuals, zoneinfo and full locale/encoding
integration), other world roots, installed tests, Make/pkgbase parity, cross
architectures, independent bootstrap, kernel/module installation, hardware/
publication and CPU/RAM/disk I/O/footprint/cache/sandbox gates remain open. Make
stays production/default. BIP stays excluded. No host installation, upgrade,
publication or reboot occurred.
