# Native bsdtrace component qualification

2026-11-01. Make remains the production/default backend. The native amd64
candidate now owns all fourteen maintained C units, source-header ABI closure,
library dependencies, complete nine-record installation and unchanged original
suite installation. Eleven original safe ATF cases pass. No production C,
header, original test body or timeout changed. This does not establish live
hardware tracing, cross-userland or a complete native world/kernel/package build.

## Source and configuration ownership

Ordinary rules_cc compilation declares the original fourteen C sources and
original ipt/elf/dwarf/z/m library order. GNU C17 and PIE are explicit, matching
Make. The compiler's current default also selects C17, but the target no longer
relies on that default. All fourteen actual final compile actions preserve
source hashes and the 763 original Make source/header prerequisites under
/usr/src, including the source-tree HWT/user ABI headers. Native physical
processor-trace include roots occur in Make order before the separately
generated libipt public header. Make itself uses the tracked physical
intel-pt.h source header, whose unused version macros still contain template
tokens; this migration does not silently replace that selected source.

The new sys/sys and sys/vm providers list actual source headers and restrict
visibility to this consumer. There is no production Make interpretation,
source copy, generated BUILD substitute or fallback to undeclared host headers.
Current component qualification is amd64 only; ARM64/RISC-V userland remains
open despite the broader HWT framework's architecture support.

## Installation and artifact comparisons

All nine Make component records match: /usr/sbin/bsdtrace, two debug directories,
its separate debug file, compressed bsdtrace.8, /usr/include/bsdtrace_ptwrite.h,
the tests directory and both original test-package files. Package ownership is
bsdtrace (including dev/debug tags) and bsdtrace-tests. Compressed manual,
public header, installed test script and Kyuafile bytes match literally. Both
actual Make/native installed program debuglink CRC checks pass.

The final immutable program capture matches the independent Make ELF contract,
PIE/hardening, imported/exported versioned symbols and exact NEEDED order.
Section names agree; only seven DWARF sections differ: .debug_abbrev,
.debug_aranges, .debug_info, .debug_line, .debug_loc, .debug_ranges and .debug_str.
No runtime section difference is reported. Full ELF bytes differ; this is not
a proof of complete behavior, hardware operation or full ABI equivalence.

## Original tests and remaining runtime gates

All thirteen unchanged original cases are installed. Eleven execute through
the maintained native ATF adapter with eleven reported passes and no skips:
usage_surface, list_runs, decode_missing_files, decode_empty_trace,
decode_corrupt_meta, decode_truncated_pt, exec_requires_command,
trace_requires_pid, option_validation, decode_capture_env and decode_extended_meta.
These exercise CLI validation, read-only HWT availability reporting and offline
robustness using temporary inputs. They do not activate host tracing or alter
services, clock, modules or installed files.

Two installed-path cases remain explicit disposable-guest gates:
ptwrite_header_compiles consumes /usr/include/bsdtrace_ptwrite.h and cc;
meta_unparsable_warns consumes /boot/kernel/kernel. Neither was counted as a
native pass, and host installed files were not substituted. Live HWT/Intel PT,
root/credential boundaries, exec/trace capture and replay, source/kernel ABI
interaction, buffer loss/overflow and recovery still need the real hardware
integration suite. Native pkg creation/dependencies/publication, full system
composition and controlled CPU/disk-I/O/memory performance also remain open.

## Evidence and corrected audit provenance

All paths below are under /usr/obj/usr/src:

- bazel-bsdtrace-make-r2-20261101: fresh independent maintained Make program
  and NO_ROOT installation, baseline SDK/profile checks and sixteen jobs.
- bazel-bsdtrace-resume-revalidation-20261101.json: all 16,835 saved SDK and
  Make bindings/staged outputs match the actual resumed host, zero mismatches.
- bazel-postupgrade-sdk-20261101: immutable fresh SDK preparation and complete
  input/snapshot verification. The old SDK's changed /usr/bin/kyua rejection,
  old Make mismatch and deliberate r2 cancellation remain recorded in
  BSDTRACE-CHECKPOINT.md; no old receipt was rewritten.
- bazel-bsdtrace-qualification-r3-20261101: passed source/frontend build and
  eleven original cases after resumption. The program actions were cached
  from the earlier canceled r2 run. bazel-bsdtrace-parity-r1-20261101 retains
  its passing artifact/install checks and the initial failed compile audit,
  which correctly refused to count absent actions as verified.
- bazel-bsdtrace-qualification-r4-20261101: final explicit-C17 candidate,
  passed maintained build-bsd bazel-test receipt, thirteen selected targets,
  eleven reported passing cases and direct fourteen-compile action evidence.
- bazel-bsdtrace-parity-r2-20261101: immutable receipt/target/output/hash-bound
  ELF, install, literal payload, debug CRC and compile-input reports/scripts.
- bazel-bsdtrace-r4-disk-budget-20261101.json: warm final execution guarded by
  an 18GiB minimum start and continuous 16GiB free-space floor; no interruption.

The resumed broad dependency build wrote a 7.7GB expanded execution JSON log.
It was streamed rather than loaded into memory for audit. The final warm
explicit-C17 build reported 15 actions and 4.850 seconds; its guard observed
20,967,211,008 initial and 20,343,144,448 minimum/final free bytes. These are
execution observations, not a controlled performance comparison. No disk data
or earlier evidence was deleted to pass qualification.

Existing normal format-5 targets/tests and maintained ATF/install adapters
express this component without frontend C, backend API, SDK-stager or source
qualifier changes. The maintained README/manual are updated in the same change.
The saved patch is historical checkpoint evidence; the active declarations now
include the subsequently qualified explicit GNU C17 setting.

## Observability follow-up

A bounded scan of all fourteen compiled sources found no direct DTrace/SDT
provider or explicit BSM submission. Preserve the actual source behavior;
review trace authorization/ioctl errors, target credentials, attach/exec/exit,
metadata/capture failures and dropped/lost buffers with HWT and kernel callers.
A marker scan is not evidence of complete or absent transitive instrumentation.
