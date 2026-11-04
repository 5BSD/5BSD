# Native PXE construction qualification (2026-11-04)

## Graph and inputs

The missing PXE contribution now compiles the original pxeldr.S with the
standalone i386 SDK and links the flat prefix at 0x7c00. Original source/header
owners, compiler policy, entry/script and flat-image options remain explicit.
No hosted startup objects or libraries enter this assembly link. Public data
artifacts cross the existing standalone boundary without forwarding CcInfo.

The graph consumes the native BIOS Lua client as a real dependency, applies the
original PXE client-size check, packs it through the native BTX tool as a.out,
concatenates prefix then packed loader, and aligns the complete image to 2048
bytes exactly as Make's dd conv=sync recipe. The shared byte rule gains an align
operation; it retains the existing zero/pad/check/concat operations. Block size
is a format constant from the original recipe, not a site-specific path list.
These small firmware transformations do not load an installed OS into a memdisk.

Typed loader_pxe_max_size defaults to Make's actual 530000-byte value. The
existing BIOS address setting controls the a.out entry and BTX stub. Independent
loader_pxe_probe_keyboard and loader_pxe_always_serial booleans default false.
loader_pxe_interpreter currently supports the qualified Lua producer; explicit
4th/simp selections are incompatible until their BIOS producers are completed.
There is no silent interpreter fallback or claim of complete option coverage.
The underlying Lua source-profile gates remain effective.

Shared boot_data_installation provides the image/manual manifest and real
account/mtree-derived archive, including man/mancompress/split_manpages policy
and the existing declared epoch. The ordinary build-bsd format-5 path accepts
these public targets/settings; no new C dispatcher or staging exception is used.

## Original references and composition evidence

All evidence roots below are under /usr/obj/usr/src.

- bazel-pxeldr-make-r1-20261104: fresh original Make prefix, object, packed
  loader, dd-composed image and actual installation records, with sixteen jobs.
  Its original loader prerequisite is the retained world SDK's older client.
  That SDK input differs from the current native client; raw complete-image
  equality against this first reference would be an unsupported claim.
- bazel-pxeldr-{probe,serial,site}-make-r1-20261104: fresh actual original Make
  builds for keyboard-only, serial-only and both console selectors. The combined
  case also uses original WITHOUT_MANCOMPRESS/WITH_MANSPLITPKG. All references
  preserve their original SDK inputs and actual package metadata.
- The maintained reference helper now accepts presence-only NAME=1 selectors in
  either the component basename namespace or BOOT_<component> namespace, matching
  actual Make BOOT_PXELDR_* controls. Arbitrary assignments/expansions, reserved
  global configuration, bare/foreign namespaces and profile collisions remain
  rejected. The existing selector tests include those positive/negative cases;
  no ad hoc program-name allowlist or arbitrary Make-variable interface is added.
- bazel-pxe-r1/r2/r3-20261104: native pipeline and real archive through the
  maintained frontend. R2 executes the new four-method PXE artifact test; final
  R3 passes 29 selected targets (two execute, 27 reuse unchanged cached results),
  including the updated reference selector validator. Wrapper target/XML counts
  are not unittest-method counts.
- bazel-pxe-{probe,serial,site}-r1-20261104: all three nondefault profiles pass
  the actual four-method artifact test. The combined case uses a tighter 490000-
  byte client bound and plaintext manuals in bootloader-man.
- bazel-pxe-controls-r1-20261104: all four native assembler objects and flat
  prefixes are whole-byte identical to fresh original Make. Each unmodified
  reference's packed image is checked against its actual retained SDK input.
  Original BTX and dd commands are then executed using the independently
  qualified original BIOS Lua compiler/link/strip control from
  bazel-bios-loader-filename-control-r2-20261104. Complete packed-loader and PXE
  bytes match native in all four profiles. That original-control client is
  hash-bound to its earlier proof; no native output is substituted as a reference
  input, and no SDK or original reference file is replaced. Production consumes
  the native graph, never a comparison-control artifact.
- bazel-pxe-overflow-r1-20261104: the actual frontend with client limit 1 fails
  its BSDBootImageBytes check action. FAILED.json and execution logs are retained.
- bazel-pxe-interp-r1-20261104: explicit 4th selection fails the incompatible
  target check; it does not construct a Lua fallback. This rejection is retained.
- bazel-pxe-review-r1-20261104: four compiler contexts and twelve canonical
  original consumed source/header pairs; 28 profile/producer associations bind
  compilation, link, guard, BTX, ordered concatenation, alignment and archive.
  Every original compiler operand remains in order after explicit ABI/SDK/
  dependency/include-view/output plumbing accounting. Receipt-bound SDK tools
  are inspected through their stable repository paths, not mutable execroot
  symlinks. Two actual installed files are checked across four profiles (eight
  comparisons), including package tags, exact manual bytes, native image archive
  payloads and original /boot directory metadata. Thirty-two previous boot
  products remain whole-byte identical: the sixteen EFI images, BIOS Lua image/
  archive, combined boot2, seven legacy BIOS/BTX images and three GPT-family
  images with their archives.

The host test inspects actual ELF32 identity, a.out entry/layout, checked client
identity, complete prefix/loader order, zero padding, archive metadata and
package tags. It executes the real byte helper at the observed client boundary
and one byte below; failed checks preserve the prior output. Alignment tests
cover empty, short, exact-block and multi-block boundaries. Existing BIOS Lua
inspection covers the embedded loader's complete BTX/kernel/client structure.

## Remaining acceptance

DHCP/TFTP/PXE firmware execution, network-driver/hardware compatibility and
normal OS startup are not established by these construction tests. Alternate
BIOS/IA32 profiles, full world/kernel/pkgbase/hardware publication, reproducible
bootstrap, debugger/source mapping, broad sandbox/cache/incremental acceptance
and CPU/memory/disk I/O/storage comparison remain open. Client timing/RSS is
not a measurement of the persistent JVM or complete system build.
Make remains production/default. BIP remains excluded. No host installation,
upgrade, reboot, package publication or VM execution occurred in this batch.
