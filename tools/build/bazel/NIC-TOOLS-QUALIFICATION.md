# Native NIC utilities — 2026-11-01

## Source and build scope

The configured amd64 world selects `usr.sbin/cxgbetool` and
`usr.sbin/mlx5tool`. Both now have native rules_cc programs, installation
manifests/archives and Python tests. Make remains production/default. Neither
program's C source nor its manual was changed. These are userland utility
candidates, not NIC driver, firmware or hardware qualification.

- cxgbetool owns the ten maintained C entries in original object order. Its five
  included register-definition C tables are `cc_library.textual_hdrs`, not extra
  standalone translation units. `tcb_common.h` is a normal header. The existing
  native libpcap dependency retains its default OFED selection and runtime.
- mlx5tool owns its single maintained C source. Its driver interface header is
  owned by `sys/dev/mlx5:tool_headers`, preserving `dev/mlx5/mlx5io.h` spelling.
- cxgbetool's Make `-I${SRCTOP}/sys` requires actual source headers. Narrow
  providers own its observed closure: 45 sys/sys, four sys/net, one netinet,
  one netinet6, and the one cxgbe ioctl header. No broad kernel-header glob or
  copied SDK replacement was introduced. Register tables remain original files.
- The actual WARNS=2 (cxgbetool) and WARNS=6 (mlx5tool) ordered warning vectors,
  Clang exceptions, GNU C17, PIE/PIC macros and hardening policy are declared.
  WERROR follows the existing typed configuration. No common toolchain changes.

## Independent evidence

All evidence is under `/usr/obj/usr/src`, with input/receipt bindings retained.

1. `bazel-nic-tools-make-matrix-20261101.{py,json}` built and staged fresh
   independent Make references in two jobs with eight compilation workers each.
   Both `bazel-{cxgbetool,mlx5tool}-make-r1-20261101/receipt.json` passed.
2. `bazel-nic-tools-qualification-r1-20261101` passed the normal format-5
   `build-bsd bazel-test` frontend with six targets, two test wrappers and 16
   workers. No additional frontend argument or backend dispatch is required.
   Its explicit disk guard stayed above the 16 GiB reserve without interruption.
3. `bazel-nic-tools-link-r1-20261101.*` binds both actual CppLink actions and
   captured parameter-file digests to the execution log and qualification
   receipt. The selected records include all eleven actual program compiles.
4. `bazel-nic-tools-audit-20261101/report.json` passes all eleven source actions:
   exact ordered Make warnings, exact command-line macros, required compiler
   flags, linked object digests/order and 384 Make prerequisite input hashes
   (320 cxgbetool, 64 mlx5tool). This proves declared input coverage, not a
   compiler syscall file-read trace. Source recipes and dependency files remain
   independent Make outputs.
5. `bazel-{cxgbetool,mlx5tool}-elf-audit-r1-20261101.json` uses immutable native
   payload captures and passes ELF identity, interpreter, ordered NEEDED,
   import/export/version and hardening comparisons. No RPATH, TEXTREL, W+X or
   executable-stack exception was permitted.
6. `bazel-nic-tools-install-audit-20261101/report.json` passes ten installed
   paths and four debug-link CRC checks across both components. Programs,
   debug files and compressed original manuals retain root:wheel metadata and
   the source-owned `cxgbe-tools` / `mlx-tools` package tags. Literal manual
   payloads match Make. Native pkg archive production is still a wider gate.

## Tests and actual object differences

Each native Python wrapper passes four unittest methods as an ordinary user:

- cxgbetool short/long help, absent device/command, and absent command;
- mlx5tool help, absent action, unknown option, and invalid PCI selector.

Source review confirms these specific paths return before the utility opens a
device. The selected libpcap OFED provider constructors register providers;
these cases do not request RDMA enumeration or open a NIC. The eight methods
exercise actual unmodified programs with declared native runtime DSOs. Bazel
XML reports two wrapper cases; the original unittest logs report four methods
per wrapper. These are newly added parser tests, not an existing hardware suite
silently reduced to pass.

`bazel-nic-tools-object-review-20261101/report.json` compares the actual linked
objects retained with digest checks. All eleven raw `.text` sections are exact
Make matches. For mlx5tool, all final runtime sections match; only seven DWARF
sections differ. For cxgbetool, every object's non-debug sections match except
`tcb_common`'s `.rodata.str1.1`, `.rela.rodata` and `.symtab`. Its actual printable
string difference is only the relative native source filename versus Make's
absolute `/usr/src/.../tcb_common.c` diagnostic. Original section bytes and
string differences are retained. The final cxgbetool ELF has `.text`, `.rodata`
and dynamic/relocation layout differences; this does not establish complete
relocation or runtime equivalence. No input was rewritten or absolute source
path embedded to force binary equality.

## Remaining gates

- Real NIC register/filter/TCB/firmware/dump/reset/EEPROM operations need suitable
  hardware and separate authorization. No host device access, flash, install,
  service change, VM or reboot was performed here.
- Cross-userland, OFED-disabled/transitive-library alternatives, complete package
  creation/publication, whole-system startup and controlled performance/cache
  qualification remain open. This component does not claim them.
- The eleven production C sources contain no DTrace/SDT provider, FIDL generator
  or explicit BSM audit interface. No existing instrumentation was dropped.
  Review auditing of privileged firmware/reset/register operations separately;
  this migration does not invent a new audit policy.
