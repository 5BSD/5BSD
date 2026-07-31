# Capability components validation record

This record separates tests that have actually run from tests that require a
privileged or live system.  A skipped privileged test is not a pass.

## Unprivileged object-tree validation

Validation was last run on July 31, 2026 from
`/usr/obj/usr/src/amd64.amd64`.  Every affected library, provider, serviced,
servicectl, and test program built with the normal FreeBSD warning policy
(`-Werror`).  The channel and every DTrace-instrumented provider also built
with `MK_DTRACE=no`, catching probe-only unused state.  Kyua reported 158
passed, zero failed, zero broken, and 96
privileged tests skipped across these suites:

- `libcapability`, `libchannel`, `libservice`, `libcapbundle`, and
  `libshmring`;
- `libfilesystemcmp`, `libnetworkcmp`, `liblogcmp`, `libnotifycmp`, and
  `libtracecmp`;
- `filesystemcmp`, `networkcmp`, `logcmp`, `notifycmp`, and `tracecmp`;
- `serviced` and `servicectl`.

All component bundle manifests passed source-built `servicectl verify`.
The pkgbase metadata, package dependency, package suffix, typed-discovery,
audit-event, and DTrace-provider source contracts passed in
`component_examples_test`.

The FileSystem path-context suite passed 15 of 15 cases, covering independent
logical current directories, absolute and relative resolution, root-clamped
`..`, transactional failed `chdir`, caller-owned duplicate handles, concurrent
contexts, path-only handle I/O and release, exact root/cwd-handle cleanup,
length limits, and rejection after `fork`.

The serviced on-demand state suite passed 4 of 4 focused cases.  It verifies
that pending work is bound to the exact provider label, PID, and launch
sequence; same-name waiters remain isolated across replacement providers;
timer identifiers wrap without leaving their reserved range or colliding with
a live timer; and failure to register a timeout on the kqueue is immediately
terminal rather than leaving a retained request without a deadline.

The latest object-tree test database files are under `/tmp` with names
beginning `capability-audit-final-` and ending `20260731.db`.  They are
diagnostic artifacts, not release evidence that should be packaged.  The
newly added root-only client-death, supervisor-death, and inherited-channel
tests, plus the strict component-bootstrap wire rejection matrix, were
enumerated and skipped, not counted as passes.

## Full-world build status

A normal `buildworld` reached unrelated existing VSOCK test code and stopped
because `tests/sys/kern/vsock_rx_harness/virtio_vsock.c` includes the absent
`dev/virtio/vsock/virtio_vsock_var.h`.  A second build with tests disabled
reached unrelated VMM/sysdecode code and stopped because `VM_GET_CPU_COMPAT`
uses an incomplete `struct vm_cpu_compat`.

The logs are:

- `/tmp/capability-buildworld.log`
- `/tmp/capability-buildworld-notests.log`

These failures do not validate or invalidate the component changes.  A clean
full-world and pkgbase artifact build remains a release gate after the
independent base-tree failures are repaired.

## Privileged and live release gate

Run the following on a disposable test host built from the same source and
object trees:

```sh
cd /usr/src
doas kyua test -k /usr/obj/usr/src/amd64.amd64/lib/libchannel/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/lib/libservice/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/serviced/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/servicectl/tests/Kyuafile
```

Also run the installed component suites under `/usr/tests/lib` and
`/usr/tests/usr.sbin` so packaging and installed-path assumptions are tested,
not only object-tree paths.  The live run must demonstrate:

- Capsicum entry and descriptor-right confinement;
- mac_capability transfer, close-on-fork, close-on-exec, peer-death, and
  coalition teardown behavior;
- multiple provided names, lazy per-name activation, provider crashes,
  requester crashes, stale-reply rejection, and serviced death;
- FileSystem scratch, persistent, and read-only bundle namespaces across
  restart, including quota reconstruction and durable sync;
- Network TCP and UDP over IPv4 and IPv6, DNS, nonblocking connect and accept,
  deadlines, cancellation, and socket exhaustion;
- Log batching, ring pressure, loss accounting, flush, close/reopen, fork, and
  sink failure;
- Notify default-deny enforcement and identity-bound ACL enforcement before
  any publish, subscribe, or timer grant is enabled;
- Trace raw-descriptor denial by default;
- successful and denied OpenBSM audit records and live DTrace probe arguments;
- jail-scoped startup and component coalition membership.

Finally build pkgbase packages with the project’s normal suffix matrix and test
fresh install, upgrade, and removal in a disposable boot environment.  Confirm
that removing a provider does not remove a typed client library needed by
another package, and that removing a library is rejected while a dependent
provider or application remains installed.
