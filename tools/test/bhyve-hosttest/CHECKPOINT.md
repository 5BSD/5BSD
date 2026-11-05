# Gen8 checkpoint, 2026-11-05

This commit saves the reviewed HyperTrace aggregation correction, console
lifetime/raw L2 console fixes, and expanded qualification kit. Live validation
of the latest changes is still pending. No upgrade or reboot is part of this
checkpoint. The separate devices-sr virtio-fs restore EBUSY is unresolved.

The kit was previously staged at
/usr/obj/5BSD-otel-validation/gen8-stall-fix/kit. Its source is now tracked here.
Generated helpers and guest images are not tracked. Run images/refresh-tools.sh
with the matching world object directory to populate bin/ and guest-bin/ before
selftest or image construction. Create a writable
/usr/obj/5BSD-otel-validation/hosttest-results first for the full selftest. Use IMAGES under /usr/obj for image builds.
Historical .bak-* files retained here are inputs to fail-before regressions,
not executable upgrade helpers. Existing local validation artifacts remain at
/usr/obj/5BSD-otel-validation/gen8-stall-fix.

Evidence before this checkpoint:
- Full kit selftest PASS (selftest-expanded-final.log).
- Five expanded negative-path test groups PASS (coverage-test.log).
- Production aggregation regression fails on Gen8 and passes on candidate;
  ASan/UBSan also pass. Full libdtrace builds via its maintained Makefile.
- Independent review completed with reported findings addressed.
- Rebuilt guest matches generation and overlay, capability plane ON.

Required live checks: individual and combined HyperTrace counts, distinct
per-VM OTLP resources, and nested scratch storage integrity before/after L1
restore. Root commands are retained in ROOT-VALIDATION.md beside the staged
kit's RECORD.md. The user runs privileged tests under the standing handoff.
No claim of fixed historical freezes, all-device support or epoch-reuse
isolation follows from the unprivileged tests.

Build frontend assessment: existing libdtrace and vsock_e2e targets cover
source changes. This standalone qualification kit changes no publication,
staging, signing or build security policy; no build-bsd frontend update is
required. Permanent publication still uses the maintained system workflow.

## Make and Bazel

Make builds all eight C helpers through bsd.progs.mk. `make check` runs the
unprivileged failure-path and real-PTY regressions against those built helpers.
Use `make obj` first so standard /usr/obj object directories are available.
The aggregation fixture has `make check` in ../libdtrace-aggregate.

Bazel owns native C targets under //tools/test/bhyve-hosttest:helpers and the
matching //tools/test/bhyve-hosttest:regression_test. The aggregation fixture
is //tools/test/libdtrace-aggregate:aggregate_vm_test, backed by a native cc_test
beside libdtrace and its actual shared-library dependencies. Neither Bazel test
shells out to Make. Run through the maintained build-bsd/native-qualify source
graph frontend with the selected SDK and offline inputs. These are native
FreeBSD AMD64 tests; they do not run privileged guest or kernel probes.
The normal production libdtrace Make and Bazel targets already own
 dt_aggregate.c; no alternate publication pipeline is introduced.

These Make/Bazel regression targets run the focused failure-path and PTY
checks, not the full historical `hosttest.sh selftest`. The console lifetime
fixture is also available as
//tests/sys/kern/vsock_e2e:console_lifetime_test; its Make installation and
host-tools-selftest integration remain in tests/sys/kern/vsock_e2e.

Checkpoint build validation: Make built all eight helpers and passed the five
focused groups, real-PTY checks and aggregation fixture. Native Bazel built the
helpers and libdtrace dependency graph and passed all three test targets
(aggregation, focused/PTY and console lifetime). Qualification receipt:
/usr/obj/5BSD-otel-validation/gen8-stall-fix/bazel-checkpoint-r6/receipt.json.
The fresh SDK passed integrity verification; no download or root action was used.
