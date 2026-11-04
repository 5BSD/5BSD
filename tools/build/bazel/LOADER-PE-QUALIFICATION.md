# AMD64 loader debug, PE and installation contracts (2026-11-04)

## Source-owned build interfaces

The selected Lua profile now provides loader_lua_symbols, loader_lua_debug,
loader_lua_efi and install_manifest in //stand/efi/loader. The debug split uses
the existing objcopy rules. The PE action uses the actual source-built elfcopy
in its execution configuration, native declared runtime libraries, and exactly
Make's section list, including command and Lua linker sets.

The format-5 string setting //tools/build/bazel/config:loader_source_date_epoch
selects the PE timestamp independently from loader version metadata. Its default
1704067200 is the policy maintained by stand/efi/Makefile.inc, not a copied test
identity or current clock. The generic image rule accepts either an explicit
string or a typed setting and rejects missing, conflicting and out-of-range
values. No machine-specific key, source path or test image is a hidden default.
The qualification still explicitly selects the existing development verifier
header policy; it does not qualify production trust roots, signatures or boot.

The selected install manifest owns /boot/loader_lua.efi (0555), common help
(0444), and the hardlink /boot/loader.efi. Owner/group are root/wheel with the
maintained bootloader package tag. INTERNALPROG leaves the symbol/debug files as
build artifacts. Directory policy belongs to the aggregate stage's maintained
mtree, not a second manual directory inventory in this component.

The elfcopy execution runtime has a public component-owned filegroup. Its source
library definitions are shared with functional tests. The SDK execution copy of
the ELF interpreter is declared alongside libgcc_s and the native source-built
libraries. Search paths now include only shared-library directories, excluding
Python data and interpreter-only directories. The initial Python path was 14,714
bytes; the final action/runtime audit records 284 bytes. Processwrapper
still uses the host ELF interpreter; equality to the SDK copy is attested rather
than treated as filesystem isolation. Full sandbox qualification remains open.

## Retained evidence

Paths below are under /usr/obj/usr/src:

- bazel-loader-pe-amd64-r1-20261104 and bazel-loader-pe-amd64-final-r1-20261104:
  successful maintained frontend builds, all 16 logical CPUs. The final source
  includes the filtered search paths and explicit interpreter input.
- bazel-loader-pe-amd64-reference-r1-20261104: actual recorded Make objcopy and
  elfcopy recipes run with original SDK tools on the closed raw original link
  and its independent filename controls. Inputs/commands/tools are bound; this
  reference does not establish a complete hermetic host runtime closure.
- bazel-loader-pe-amd64-review-r1-20261104 and
  bazel-loader-pe-amd64-final-review-r1-20261104: the complete PE bytes match the
  filename-controlled original. PE32+ AMD64 application identity, selected
  timestamp and entry agree; all runtime ELF sections/program headers survive
  debug splitting. Debug data exists separately and the debuglink filename and
  CRC are correct. All three installation file/link metadata contracts and help
  bytes match Make; the original installation's hardlink inode is checked.
- bazel-loader-pe-amd64-future-r1-20261104 and its future-review directory:
  explicit 2147483649 timestamp passes through format 5 and produces the exact
  original recipe's PE bytes. Full ELF and debug artifacts remain unchanged.
  Its actual successful noncached spawn inventory contains only BSDEfiImage.
- bazel-loader-pe-amd64-invalid-review-r1-20261104: 4294967296 is rejected with
  the intended unsigned timestamp analysis error and no successful receipt.
- bazel-loader-pe-amd64-restored-r1-20261104: default restoration again executes
  only BSDEfiImage. The timestamp-cycle review binds exact image restoration.
- bazel-loader-pe-elfcopy-runtime-review-r1-20261104: captured actual native
  elfcopy and its supplied libraries, with every digest bound to the successful
  image action. All 12 recursively needed libraries resolve within those inputs;
  the host interpreter matches the SDK copy. The final audit repeats this with
  the explicit interpreter input and filtered Python library search path, in
  bazel-loader-pe-elfcopy-runtime-final-review-r1-20261104.
  timestamp-cycle-review.json in the final image review binds restoration,
  unchanged final PE bytes and the 14,714-to-284-byte search-path reduction.

These are real loader transformation and configuration checks, not a fresh run
of every generic EFI fixture regression test. Earlier generic fixture tests and
other profiles do not establish this loader's firmware behavior. Full object and
DWARF byte/source-lookup parity remain open; no comparison rewrites native or
raw original payloads, and no new assertion suppression or date fallback exists.

## Build cost and remaining gates

The first native elfcopy tool closure took about 453 seconds of Bazel client
wall time. It builds libc/libthr's DTrace generation dependency, including the
existing full dtrace tool's C++/HyperTrace/telemetry/protobuf dependencies.
Subsequent timestamp changes execute only PE conversion. These observations are
not full-system CPU, memory, physical I/O, disk-space or warm-cache performance
qualification: a persistent Bazel server is not fully accounted by client time.
Review cold bootstrap closure cost and broad SDK invalidation at those gates.
No DTrace source or probe was removed to shorten the build.

Actual archive staging, pkgbase file/directory coverage and installation,
production policy/signature inputs, firmware execution, ARM64/RISC-V entry/image
profiles and alternate loader options remain required. Complete world/kernel/
module, bootstrap/output-query/sandbox/cache, separate hardware and verified
combined publication and comparative performance also remain open. Make stays
production/default. BIP remains excluded; no host install, upgrade, reboot or VM
was performed in this qualification.
