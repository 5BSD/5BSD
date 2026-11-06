# Original AMD64 system-call test construction (2026-11-06)

## Complete selected construction and installation

All sixty-three original AMD64 system-call ATF programs build natively. Their
128 non-directory installation records match original Make: sixty-three stripped
programs, sixty-three split debug files, exact Kyua and the empty root-owned
truncate fixture. Owner/group/mode/tags/flags and test/debug directory attributes
match. All sixty-three executable ELF identity, PIE/interpreter, hardening,
dynamic symbol/version and ordered dependency contracts match; native and Make
debug filenames/CRCs are checked. Raw ELF/debug equality is not claimed.
Original C sources, Makefiles and test expectations are unchanged.

Imported programs declare the native NetBSD compatibility archive and headers.
getpid explicitly links the native thread ABI; timer_create explicitly links the
native realtime ABI. Both mlock and setrlimit retain the additional original
mlock_helper.c translation unit. The WNOHANG program declares t_wait_noproc.c as
a textual input, preserving the original inclusion rather than compiling it a
second time in that program. getgroups preserves its per-source fortify opt-out.
The generated fixture is empty by definition in original Make (/dev/null via dd);
a declared write_file action produces the same zero bytes. Package metadata
sets root:wheel 0600, without requiring host-root writes during construction.

Original IPC Kyua is_exclusive="true" metadata is retained exactly. Runtime
adapters also tag the four message-queue programs exclusive. An initial comparison
caught native boolean serialization instead of Make's quoted string; preserving
the original representation restores exact Kyua bytes, without changing the
comparison or losing the metadata.

## Original metadata and bounded execution

All 283 original ATF case registrations and full -l metadata match actual Make
programs. All 72 cleanup declarations, original root/unprivileged requirements
and custom deadlines match their native adapter policies. Nineteen reviewed host
cases pass with no skips or expected failures: errno, singly linked/tail queues,
swapcontext, PID/process/thread identity, session IDs, umask and descriptor basic/
error/mode operations. Descriptor maximum-limit cases are deliberately excluded
from the host cohort. Cleanup runs in private case directories as originally
specified. The final 20-target report includes these nineteen original cases
plus the source-settings helper. Repeated qualification preserves the reviewed
installation output hashes and can reuse passing bounded host test results.
This is not mutation testing or a complete cache/incremental qualification.

The other 264 cases are built/installed but unexecuted. They retain explicit
manual deferred adapters and must be reviewed/exercised in disposable guests,
including global IPC exhaustion, root operations, networking, clock/resource/
process limits and wired-memory sysctls. Manual adapters are not a qualified VM
harness. Cases needing installed ownership, absolute tools or system state must
use actual installed archives in the guest; in particular a user-owned Bazel
runfile does not establish the truncate fixture's root-owned 0600 semantics.
No host global-state test or VM is run by this contribution.

## Declared action review

A read-only aquery derived from the maintained frontend configuration verifies
that both registered regular/PIC WNOHANG compile actions include the original
textual source, and that mlock/setrlimit each have both original translation
units. Ten registered compile actions represent five translation units; these
are configured action inputs, not ten executed compiles or a mutation/cache
invalidation experiment. Final linking chooses its required object variant.

The first diagnostic query omitted the explicitly selected JDK environment and
encountered the unrelated host local_jdk discovery error. Repeating with the
request's declared staged JAVA_HOME/JAVABIN succeeds. A second diagnostic review
incorrectly assumed one registered action per source; the final review checks
both actual native variants explicitly. These are retained diagnostic attempts,
not failures hidden by dropping a dependency or bypassing a sandbox.

## Evidence

- Maintained build-bsd request:
  /usr/obj/usr/src/bazel-libc-sys-request-r2-20261106/inputs.json
- Final native build/runtime receipt:
  /usr/obj/usr/src/bazel-libc-sys-native-r4-20261106/receipt.json
- Independent original Make installation/ELF/debug review:
  /usr/obj/usr/src/bazel-libc-sys-review-r2-20261106/review.json
- All original metadata, 19-case selection/outcomes and stable output bindings:
  /usr/obj/usr/src/bazel-libc-sys-case-review-r1-20261106/review.json
- Configured textual/helper compile input review:
  /usr/obj/usr/src/bazel-libc-sys-actions-review-r3-20261106/review.json
- Original Make control:
  /usr/obj/usr/src/bazel-libc-installation-make-r1-20261105

Artifacts resolve through completed receipt/manifest/content hash checks, not
mutable bazel-bin links. Final archive/record/directory hashes match independently
reviewed r2 outputs. r1 and review-r1 retain the original Kyua formatting mismatch;
aquery review-r1/r2 retain the diagnostics above. Requests use all sixteen CPUs,
explicit SDK/bootstrap inputs, production-malloc selection and original non-NIS
qualification settings. These are selected AMD64 results, not ARM64/RISC-V tests.

The existing build-bsd format-5 interface builds/captures this contribution and
correctly reports its actual cases; no new C frontend schema is necessary.
Declarations, manual, completion plan and audit log are updated together. This is
unsigned qualification, not publication, verified boot or full system bootstrap.

## Open gates

Qualify the remaining 264 cases with their actual guest environments and global
state/cleanup controls. Complete remaining libc gen/ssp/iconv installation work
and full test-parent traversal, other ABI/options, independent complete world/
install/debug/pkgbase checks, native kernel/module boot/runtime, reproducible
bootstrap, sandbox/cache/incremental qualification, normal system services,
controlled CPU/memory/disk-I/O/storage comparisons and combined hardware
publication. Make remains default and full-tests guards stay in place. BIP stays
outside scope.
