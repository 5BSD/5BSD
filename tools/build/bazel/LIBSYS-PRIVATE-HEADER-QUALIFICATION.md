# Private libsys implementation dependency (2026-11-04)

The original libsys Make recipe declares bcopy.c as a textual dependency of
memcpy.c. The native sys_objects group had instead published bcopy.c in its own
textual_hdrs, propagating this implementation include through native libc's
link interface into unrelated consumer compile inputs. It now declares a
package-private header provider consumed via implementation_deps. Actual
implementation inputs remain declared; no include path, compiler option, source
body, archive membership, ABI, installed metadata or visibility grant changes.
This is an idiomatic CcInfo compilation-context boundary, not a source rewrite.

## Evidence under /usr/obj/usr/src

- bazel-libsys-private-header-native-r1-20261104: maintained build-bsd format-5,
  sixteen jobs and the same SDK/configuration as the previous NIS qualification.
  Six selected tests pass: libc runtime and static/shared libsys syscall tests
  execute; source settings and both NIS alias tests are cached.
- bazel-libsys-private-header-review-r1-20261104: all four newly logged NIS
  consumer compile actions exclude bcopy.c. Their raw objects match prior native
  objects exactly, preserving the prior independent original Make contracts.
  All nine NIS archive/request/directory products match prior captures exactly.
  Explicitly captured native libc.so.7 and libsys.so.7 match the hashes recorded
  in all three prior actual consumer link inputs; mutable bazel-bin is not used
  as comparison evidence. Raw actual outputs are hash-checked and retained.
- Its input-delta.json proves every consumer loses exactly bcopy.c, adds no
  declared input path and retains the identical compiler argv. This isolates the
  declaration change; it is not a wall-time or memory improvement measurement.
- bazel-libsys-private-header-actions-r2-20261104: structured aquery inspection
  verifies eight configured consumer variants (regular/PIC for four sources)
  exclude bcopy.c while both libsys memcpy variants retain it. Four consumer
  actions actually execute in the native build; configured actions are not
  called executions. The first query's union returned extra rule actions; its
  strict parser rejected that result. A single outer action-filter chain narrows
  the query. Its initial count assertion correctly rejected the mistaken
  four-configured-actions assumption; the retained raw graph contains ten.
  The final parser requires exactly both variants of all five source files.
  See https://bazel.build/query/aquery for action filter and jsonproto semantics.

## Scope

The current libsys group still shares private implementation inputs across its
own regular/PIC compile group. This change removes leakage to downstream public
consumers. It does not claim Make's per-source invalidation granularity for every
internal libsys source. The unchanged repeat in bazel-libsys-private-header-repeat-r1-20261104 passes
with all six test results cached. Its review (repeat.json alongside the main
review) verifies all 22 captured output records unchanged and zero actual spawn
records in the compact execution log. This is local up-to-date reuse in the
same persistent state, not a cold build, disk-cache restore or remote hit.
Executed source/header mutation controls, cold/cache-restore/location tests,
whole-system sandboxing and comparative CPU/memory/disk-I/O/resource gates remain
required. No numerical build-speed claim follows from removing one dependency.

The existing format-5 build-bsd dispatcher/backend carries this provider change
without a C/schema change. The manual, cache roadmap and completion plan are
updated in the same change. Make remains production/default; BIP stays excluded.
No host installation, module loading, publication, upgrade, reboot or VM occurs.
