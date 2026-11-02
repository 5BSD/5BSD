# Userland upgrade stopping point — 2026-11-01

## Resumed progress after that stopping point (2026-11-02)

The saved host/SDK/reference identities were revalidated without rebinding old
receipts. Native wpacommon and hostapd_cli now pass the bounded checks in
[their qualification](WPA-COMMON-CLIENT-QUALIFICATION.md). Nine further private support libraries now pass the output/input checks in
[their qualification](WPA-SUPPORT-QUALIFICATION.md). The final four private
libraries now pass [their qualification](WPA-FINAL-PRIVATE-QUALIFICATION.md),
including all 660 object/compiler/input checks and 32 archive comparisons. All
sixteen private directories have bounded native output qualification. The
[wpa_cli client](WPA-CLI-QUALIFICATION.md) now passes four program configurations,
sixteen safe CLI/loader methods and its actual link/install/input checks. Next
WPA work is hostapd and wpa_supplicant; daemon/control/wireless runtime, cross
builds and whole-system gates are still open. The earlier paused record
and prepared-reference notes below are historical.

## Update at the next upgrade stopping point (2026-11-02)

At the user's request, userland work is paused for the November 2 kernel
upgrade. All owned build/reference/VM processes are terminal. No host install
or reboot was performed. Resume only after revalidating the changed host and
execution SDK, then continue the common/control-client tranche below.

The original stopping-point record below is historical. Native WPA private
libraries and wpa_passphrase are now qualified as described in
[WPA-PRIVATE-QUALIFICATION.md](WPA-PRIVATE-QUALIFICATION.md), including five
configuration profiles, 25 immutable ELF comparisons and 35 actual runtime test
methods. The focused source termios correction is committed separately as
6c06060029c. Make remains production/default; complete WPA/system/cross/runtime
and performance gates remain open.

Next intended tranche is wpacommon (eleven sources) and hostapd_cli (one source).
Under /usr/obj/usr/src, bazel-wpa-common-reference-matrix-20261102.json and
bazel-wpa-hostapd-cli-reference-matrix-20261102.json record four successful
independent Make configurations each. bazel-wpa-common-recipe-capture-20261102
records 22 default ordinary/PIE recipes with unchanged object bytes. No native
common/control-client declaration was added or tested. Revalidate host, source
and SDK inputs after the next upgrade before using these references.

User requested all work committed and agents stopped before a new kernel
installation. No upgrade, installation, reboot or host service/device action was
performed by this worker. Make remains production/default; BIP remains excluded.

## Committed work

- `e0383a93fcf`: default ordered-NEEDED rejection for program/shared ELF
  comparisons, real positive/negative regression, and bhyve's native ordered
  dependency correction. A fresh post-HyperTrace-merge Make reference passes
  ordered metadata and 86 install paths/four CRCs. Physical code/DOF/section and
  broader runtime/configuration gates remain open. See
  ELF-NEEDED-ORDER-QUALIFICATION.md; do not reuse the rejected pre-merge reference.
- `ce5e1d304ec`: native cxgbetool/mlx5tool (eleven unchanged C translation units),
  source-owned narrow interfaces/headers, exact warning/macro policy, package
  installation and eight non-root pre-device test methods. All eleven raw object
  text sections match Make; 384 prerequisite hashes, both strict ELF contracts,
  ten install paths and four debug-link CRCs pass. See NIC-TOOLS-QUALIFICATION.md
  for retained diagnostic/layout and hardware/cross/package/performance limits.

No unqualified WPA declaration, option flag or source change is active or hidden
in a stash. All WPA preparation below is external evidence, not native coverage.

## Fresh world discovery (terminal success)

Under `/usr/obj/usr/src`:

- `bazel-world-inventory-postmerge-20261101/inventory.json`: maintained Make
  print-dir discovery, 2,127 selected directories; identical directory set to the
  earlier refresh. Explicit profile and public loader anchor inputs retained.
- `bazel-world-components-postmerge-20261101`: all 2,127 metadata queries passed,
  zero component failures; summary, per-component rows and input hashes retained.
  This is a directory/metadata inventory, not native compile/install coverage.

`switchboard-nss` is the program in `usr.sbin/switchboard/nss-helper`. Its native
program and installation already live in the ancestor switchboard BUILD. Do not
recreate it merely because the older local-BUILD inspection queue names it.
The source-owner survey still needs rerunning/review after this new metadata.
World discovery uses real recursion; direct component metadata still requires
review for parent-export/SUBDIR_ENV effects before treating it as a source oracle.
The WPA family includes its maintained common configuration explicitly and has
no custom parent SUBDIR_ENV in the reviewed WPA recursion.

## Next intended family: WPA private libraries and wpa_passphrase

No native build has been attempted. The intended first closure is wpautils,
wpacrypto (both regular and PIE), then wpa_passphrase, followed by the remaining
WPA libraries/programs. Keep OpenSSL, EAPOL and IPv6 choices as declared build
inputs; no new flag is implemented yet. Existing format-5 typed settings can
represent a future source-owned EAPOL boolean without a one-off frontend.

Independent default Make references passed:

- `bazel-wpa-utils-make-r1-20261101`: twelve C sources, regular/PIE archives.
- `bazel-wpa-crypto-make-r1-20261101`: nineteen C sources, regular/PIE archives.
- `bazel-wpa-private-reference-matrix-20261101.{py,json}`: exact commands,
  explicit profile/SDK checks, two jobs with eight compilation workers each;
  no host installation. These internal libraries have no runtime package payload.

Parallel console recipes interleaved at TLS_DEFAULT_CIPHERS and cannot establish
exact argv by themselves. Supported Make metadata was captured with the explicit
single argv `.MAKE.MODE=meta missing-meta=yes nofilemon curdirok=yes`:

- `bazel-wpa-private-recipe-capture-20261101.*` and directory retain both actual
  Make invocations/stdout/stderr and before-object hashes. Make returned zero and
  object hashes stayed unchanged. The initial capture validator failed because
  it accidentally selected `.depend.*.o` files as if they were real objects;
  preserve this failure rather than calling that validator a pass.
- `bazel-wpa-private-recipe-review-r2-20261101/report.json` correctly reviews only
  actual objects, binds original producer commands/logs/receipts and validates
  all 24 utility + 38 crypto compiler recipes and unchanged object hashes. This
  second step is read-only review, not an invented second compiler execution.

`bazel-wpa-config-review-20261101/report.json` retains twelve read-only component
queries across all OpenSSL/EAPOL boolean combinations, their Make include hashes
and explicit option verification. Utils always has twelve sources. Crypto has
19/16 sources with OpenSSL and EAPOL enabled/disabled, and 39/36 without OpenSSL.
Passphrase has one source in each case. No alternative configuration was built
or qualified. Review all source/flag lists before expressing idiomatic native
metadata; query output must not become production Make interpretation.

## Resume requirements

1. Revalidate the new host/kernel/compiler and immutable SDK/receipt identities
   after the user's upgrade. Do not silently rebind this older baseline.
2. Recheck retained Make source/header/profile hashes before reuse; start fresh
   references when any selected input changed.
3. Preserve regular versus PIE object policy and all original library members.
   Use narrow source-owned physical header contexts (the existing
   bsd_source_headers rule is available), not broad whole-tree glob inputs.
4. For wpa_passphrase's Make reference, ensure both dependency and actual link
   selection use fresh private archives through documented specific library
   inputs; do not accept the existing world's archives as freshly built inputs.
5. Qualify original install/pkg metadata and safe passphrase computation/error
   tests, then actual configurations. No host WLAN service/network changes.
6. Continue whole-world native ownership/composition, package generation and
   full-system/runtime/performance gates. These component commits do not finish
   the overall goal.

All worker-owned build, VM and discovery sessions are terminal. The shared
Bazel server belongs to the primary workflow and is coordinated separately.
