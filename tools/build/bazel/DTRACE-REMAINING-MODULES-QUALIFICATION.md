# Syscall tracing, fasttrap and DTrace test module qualification

2026-11-01. Native component candidates now cover systrace and dtrace_test on
amd64, ARM64 and RISC-V64, plus the maintained amd64-only fasttrap and
systrace_linux selections. This closes the missing individual module
declarations in sys/modules/dtrace/Makefile for these three architectures;
whole-subtree aggregation and live tracing qualification remain separate.

## Native generated syscall tables

bsd_syscall_tables registers a native action with explicit syscall master,
configuration, Lua module closure, source-built execution-platform flua and
runtime-library inputs. A small Lua driver calls the original config merge,
compatibility selection, FreeBSDSyscall parser and table-generation module APIs.
The original generator/parser modules remain unchanged. Output kinds and paths
are declared in BUILD metadata; unsupported kinds, duplicate outputs and unsafe
relative paths are rejected. Separate output groups retain C fragments as
textual headers and public headers as headers. The action does not query Make,
invoke an ambient interpreter, rewrite generated C or consume checked-in syscall
tables as substitutes. Lua module search and dynamic-library inputs are explicit.

The native ABI target generates syscall.h, sysproto.h and systrace_args.c from
sys/kern/syscalls.master and syscalls.conf. The Linux ABI target generates its
syscall/prototype headers, syscall names and tracing-argument C from the actual
amd64 Linux master/configuration. Those generated include contexts precede the
ordinary kernel header context in their systrace consumers. Generated C remains
included source; it is not compiled as additional translation units.

The execution/target split and declared action dependencies follow Bazel's
[rule guidance](https://bazel.build/extending/rules) and
[actions.run API](https://bazel.build/rules/lib/builtins/actions#run).
This does not migrate every base-system syscall consumer or replace the
maintained syscall_symbols.bzl metadata with a generated analysis-time input.

## Module declarations

Original source files, target selection, warning flags, compatibility contexts,
forced-header order and object order are explicit. fasttrap retains its early
opt_global.h before ccompile.h and the ordinary later opt_global.h, its Intel
ISA search root, original Unicode text-preparation source and two warning
exceptions. dtrace_test uses ordinary module flags plus debug_compat.h rather
than adopting OpenZFS compiler definitions. Only the Linux variant defines
LINUX_SYSTRACE. Source-only header providers retain actual physical ownership.
No runtime C source or module ABI was changed.

## Evidence

Independent Make references passed all sixteen build/install combinations under
/usr/obj/usr/src/bazel-dtrace-remaining-make-20261101, with genuine copied/hashed
GENERIC option headers and isolated object trees. Four jobs use four workers
each on this sixteen-CPU host. Original generator references run main.lua with
a separately built flua in isolated native/Linux directory layouts, without
writing source-tree generated files.

Six final build-bsd format-5 profiles passed under
/usr/obj/usr/src/bazel-dtrace-remaining-{amd64,arm64,riscv}-{plain,ctf}-r2-20261101.
They select module/install and generated-table outputs, with no runtime test
targets. Evidence establishes:

- Sixteen module artifact comparisons and twenty-four identical install records.
- Eight plain modules byte-identical to Make. Eight installed CTF modules have
  equal section metadata/payloads except build-ID/debuglink; .SUNW_ctf matches.
  Both native/Make actual debuglink CRCs verify. Full separate DWARF identity is
  not claimed.
- All seven generated syscall outputs exactly equal both the independent
  original full generator and the maintained checked-in outputs.
- Twenty actual module compiles with matching target triples, source digests,
  exact Make warning policy and original forced-header order; forty genuine
  option-header hash checks and sixteen original link orders.
- Twenty-six compiler generated-input checks against independent generated
  reference hashes, with no original checked-in systrace C fragments in those
  compiler inputs. Twenty-six final-profile generated-output bindings match the
  original qualified generation capture.
- Both original native generator actions use source-built execution-platform
  flua, all seventeen maintained Lua source inputs, the genuine master/config
  files and the audited driver. All payloads bind through receipt, manifest and
  content hashes via qualification_artifacts.resolve.

Audit helpers and JSON records reside in
/usr/obj/usr/src/bazel-dtrace-remaining-review-r2-20261101. Initial generation
capture: bazel-dtrace-syscall-r1-20261101. Independent full-generator reference:
bazel-dtrace-syscall-review-20261101. Runner commands are retained in
bazel-dtrace-remaining-native-runs-r2-20261101. The first module analysis failure
and its diagnostics remain retained: introducing the systrace source package
required correcting its source labels and removing duplicate parent exports;
no workaround or skipped module was used to make the matrix pass.

## Integration and remaining gates

The maintained frontend already accepts explicit native target/profile inputs;
no frontend C/CLI, security policy, signing or SDK change is required. Its manual
and the native build README document this bounded gate. Make remains the
production/default backend; BIP is excluded.

Further work includes native whole-kernel/module aggregation, broader configured
kernel choices, syscall consumers beyond these providers, source-change/cache
invalidation experiments, actual load/unload and provider firing, syscall ABI
behavior, permissions, concurrency and failure paths. dtrace_test build success
is not execution of its kernel tests. No host module, tracing session, service
or storage state was changed. CPU, memory and disk performance gates remain
open; these commands are not controlled performance benchmarks.
