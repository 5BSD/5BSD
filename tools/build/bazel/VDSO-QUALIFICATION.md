# Native amd64 VDSO qualification

## Design (2026-11-02)

The source-owned amd64 GENERIC target now builds its VDSO with separate declared
compiler, linker, ELF validation/offset generation and wrapper compiler actions.
It reuses the existing native genassym/offset-check graph, selected config
headers, physical machine headers, source trampoline, linker script and wrapper.
No Make process runs inside native analysis/actions; no prebuilt Make image,
object or offset header enters the native graph. Source assembly is unchanged.

The assembler targets are ordinary rules_cc cc_library groups with explicit
PIC/LOCORE policy and the kernel toolchain's opt/debug features disabled for
this minimal assembly contract. The compiler's declared target/freestanding
flags remain visible; identical raw Make argv is not claimed. The selected
SDK's ld.lld links the image with the maintained amd64 script and explicit
source policy. This supports the staged LLVM linker, not the Make script's
optional GNU linker branch or an undeclared host linker.

The validator checks the actual ELF64 little-endian shared image and derives
its entry offset from its dynamic symbol table. Machine, OSABI, maximum size,
symbol, macro and SONAME are declared target policy inputs. The amd64 target
retains Make's 2,048-byte limit; no symbol address is hardcoded. It rejects
malformed/truncated tables, wrong identity, nonzero-based or writable/multiple
loads, external dependencies, runtime relocations, unsupported segment layouts,
inconsistent dynamic metadata and missing/ambiguous/nonexecutable entry symbols.
Only after validation does it emit an unchanged image and derived offset header.
The wrapper's additional_compiler_inputs names that validated image; its
incbin filename comes from Bazel's declared execpath. The embedded object is
not CTF converted, matching the original no-ctfconvert policy.

The unchanged build-bsd bazel-test format-5 API selects this artifact graph.
All tools and runtime inputs use existing staged compiler/linker/Python APIs;
no extra frontend C option, SDK preparation replacement, bundle/signing policy
or installation shortcut is introduced. Runnable validator regressions use a
separate host-test profile, preserving the kernel profile's no-host-test rule.
Make remains production/default. BIP is excluded. These are build-format checks,
not code signing, verified boot or protection against compromised root.

## Actual evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-vdso-amd64-r1-20261102 retains the initial failed wrapper compile:
  Bazel copts tokenization removed the quotes needed by incbin. The corrected
  source declaration escapes the literal quotes; source assembly was not
  rewritten to work around the failure.
- bazel-kernel-vdso-amd64-r2-20261102 records the successful normal frontend
  artifact profile with sixteen workers and four immutable output captures.
  tests=[] means this profile ran no runtime tests.
- bazel-vdso-validator-test-r1-20261102 records the successful standalone native
  Bazel host test: 16 actual unittest methods. Subcases exercise target/size
  policy inputs, loader permissions and mapping, dynamic/section bounds,
  dependencies, relocation tags/sections, symbol shape, strings, command output
  bytes and rejection before writing outputs. The artificial ELF fixtures are
  test inputs, not target image data used by the producer.
- bazel-kernel-vdso-review-r1-20261102 retains actual action records, reference
  preprocessing commands, source/tool hashes and immutable artifact bindings.

All four original products match Make byte for byte: sigtramp.pico,
elf-vdso.so.1, vdso_offsets.h and elf-vdso.so.o. The image is 1,552 bytes and the
actual derived offset is 0x2d0. These observations are not production constants.
The Make products belong to the earlier freshly linked Make kernel; they were
not recompiled or rewritten during this comparison. Original compiler -M queries
supply eight trampoline and five wrapper prerequisites without producing
objects. Every physical/generated prerequisite matches actual native compile
inputs. Native and Make compiler SHA256 values match; actual linker inputs bind
the unchanged maintained linker script. Linker/validator output digests bind to
final captures, and the wrapper consumes the validated native image path.
Original and incremental execution logs retain the successful producer actions
needed for that chain; no cached action is presented as a new execution.

The bounded scan finds no direct recognized SDT/DTrace/audit calls in the two
unchanged assembly sources. Existing CFI/unwind bytes are preserved by the full
product comparisons. Live signal delivery, nested signals, alternate stacks,
return-to-user behavior and lib/libexecinfo/tests/sigtramp_test.c still require
qualification with the matching isolated kernel.

Disk reserve monitoring passed. No host installation, kernel replacement,
service action or reboot occurred. Controlled CPU/memory/disk/cache performance,
complete native kernel aggregation/link/install, alternate configurations,
ARM64/RISC-V64 built-ins, full world/pkgbase/hardware publication and VM/runtime
qualification remain open. The prepared low-level amd64 cohort still needs its
own native source declarations and qualified compilation using this producer.
