# Native dtracedctl qualification (2026-11-01)

## Native ownership

The maintained BUILD owns the unchanged C source, exactly three shared daemon
protocol/IO headers, utility installation and compressed manual. Existing daemon
header consumers are unchanged. WARNS=3, WERROR, PIC/PIE, stack protection,
optimization and debug flags are checked against actual Make actions.
The source-owned `dtrace_optimized` boolean defaults false, matching Make;
true adds full `-flto` at compilation and linking. This is full LTO, not ThinLTO.
The target is explicitly amd64-only: Make excludes RISC-V LTO, and cross
userland/toolchain selection remains unqualified.

Use the maintained `build-bsd bazel-test --bazel-inputs <format-5.json>` route
with the typed `//tools/build/bazel/config:dtrace_optimized` setting. Targets
are `//usr.sbin/dtracedctl:dtracedctl`, `:source_objects`, `:install_archive`
and `:preconnect_test`. Existing format-5 setting validation, source receipt
binding, native tools, stage/archive verification and test reporting handle the
feature. No frontend C, SDK, signing or publication change is needed. The
legacy option route is not a new mapping for this component.

## Checks performed

Fresh independent maintained Make references explicitly select
WITHOUT_DTRACE_OPTIMIZED and WITH_DTRACE_OPTIMIZED. Both normal guarded native
profiles pass four targets and the six unprivileged Python test methods
(17 process invocations per profile). They cover help, absent/unknown/conflicting
actions, malformed/oversized name lists and unexpected positional names.
Every selected path returns before `open_dtraced()` in the unchanged source;
PATH is empty and the native libc/libsys are declared test dependencies.
No valid command contacts the host daemon.

Both five-record installs equal Make's path/type/owner/group/mode/tag metadata.
The compressed manual is byte-exact. Four installed debug-link/CRC checks pass
(two build systems per profile). Program ELF contracts, dependency order,
section names and runtime section bytes match in both profiles. Only
`.debug_info`, `.debug_line` and `.debug_str` differ; full ELF byte identity is
not claimed. Comparison reads hash-verified immutable qualification captures.

Actual compile audits preserve the ordered 25 warning flags, ten required
compile flags, the selected LTO flag and all 55 Make prerequisite hashes per
profile. These are hashes represented in declared action inputs, not a syscall
read trace. Plain r2 reused the r1 object; its exact output digest is matched
from the retained r1 compile to the final link input and copied object.
The actual linked plain object starts with ELF magic; the full-LTO object
starts with LLVM bitcode magic, matching the respective Make objects.
Compiler and ld.lld tool hashes, link response bytes and actual linked object
hashes were copied immediately and bound to each receipt's execution log.
The standard rules_cc compilation output group independently captures its real
PIC output; it is not misidentified as the non-PIC object selected by the link.
Both final links explicitly retain Make's `-O2 -g -gz=zlib` driver settings.

No original program, headers, manual or test body was modified. The maintained
component has no original test subdirectory; these parser tests add bounded
coverage without claiming daemon protocol execution.

## Retained evidence

All paths below are under `/usr/obj/usr/src/`:

- `bazel-dtracedctl-make-{plain,lto}-20261101/receipt.json`, build logs,
  dependency files, stage and METALOG.
- Final `bazel-dtracedctl-plain-qualification-r2-20261101/` and
  `bazel-dtracedctl-lto-qualification-r1-20261101/`: receipts, immutable artifacts,
  execution logs and original test logs/reports.
- `bazel-dtracedctl-{plain,lto}-elf-audit-20261101.json` and
  `bazel-dtracedctl-install-{plain,lto}-audit-20261101/report.json`.
- `bazel-dtracedctl-compile-audit-20261101.{py,json}` and
  `bazel-dtracedctl-install-audit-20261101.py` retain audit implementation/bindings.
- `bazel-dtracedctl-{plain,lto}-link-*-20261101.{json,params}` and
  `bazel-dtracedctl-{plain,lto}-linked-*-20261101.o` bind actual link inputs.
- Plain r1 qualification remains the original compile evidence and initial
  link profile before explicit Make driver debug/optimization flags were added;
  r2 supersedes its link qualification. No evidence was rewritten to pass.

Both final disk guards report exit zero and no budget interruption, retaining
18 GiB minimum-start and 16 GiB reserve policies. These are operational limits,
not controlled performance results.

## Open gates

Daemon socket handshake, cleanup/stats requests, authorization, deadlines,
malformed peer messages and actual HyperTrace state must run against an isolated
installed guest service. This component work does not start a daemon, activate
host tracing, or qualify live probes, full ABI, cross userland, complete native
world/kernel/pkgbase, normal startup/SSH or performance. Make remains production.
