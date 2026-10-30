# MAC ABAC QEMU integration tests

This harness boots a disposable amd64 FreeBSD guest and attaches the current
MAC ABAC module, public header, control and labeling tool, policy daemon,
sample policies, and Kyua suite as a read-only CD image. QEMU snapshot mode
leaves the base disk unchanged.

The guest image must use a kernel ABI compatible with the source tree and
provide Kyua and root console access. Run:

```sh
tools/test/mac-abac-qemu/run.sh /path/to/freebsd-amd64.raw
```

At the guest console, log in as root and run the commands printed by the
harness. The runner compiles every shipped policy format, loads the current
module, exercises the management and labeling tools, and runs the complete
suite.

`QEMU_BIN`, `QEMU_DATADIR`, `QEMU_LIBDIR`, `QEMU_ACCEL`, `QEMU_MEMORY`,
`QEMU_CPUS`, `MAC_ABAC_VM_WORKDIR`, and `SRCTOP` may override defaults. TCG is
the default, so host root access and `/dev/vmm` are not required.

## Process target-context locking regressions

`signal_context_test:signal_target_context` calls real `kill(2)` with signal zero
against a live child. It checks admission without delivering a signal, first
without a rule, then with a process-specific signal rule without context, and
finally with target UID context. In permissive mode each rule must increment the
denial counter while allowing the syscall. An affected kernel may panic or hang
in the target-context case; this is a disposable-VM-only regression.

The case skips unless explicitly configured with `disposable_vm=yes`. It also
requires enabled permissive ABAC, an empty rule table and default allow. It does
not change mode/default policy or clear existing rules. Cleanup removes only its
recorded rule ID; the child exits on pipe EOF. From the disposable guest's mounted
test directory, run the selected case with:

```sh
kyua -v test_suites.FreeBSD.disposable_vm=yes test \
    signal_context_test:signal_target_context
```

A skip is not qualification. Record the exact guest kernel and test binary,
console output and terminal result. Native compilation and test enumeration do
not reproduce or resolve the kernel issue. This case does not establish enforcing
signal-denial semantics, asynchronous origin attribution or OpenES coverage.
The regular test Makefile packages the case; the existing QEMU payload collector
copies programs from its generated Kyuafile. No new build-bsd CLI is required.

`signal_context_test:sched_target_context` uses the same isolated rule and
counter controls with real `setpriority(2)`, preserving the child's inherited
priority. Run it separately with `disposable_vm=yes`; it can expose the same
caller-held target lock problem through scheduling admission. Neither case has
been VM-qualified by compilation or enumeration. Subject/target TTY contexts still require separate regressions and lock review.
The existing packaged test program includes these cases, so the maintained
build-bsd/package workflow needs no additional CLI or staging input.

`signal_context_test:wait_target_context` calls real `waitpid(2)` with `WNOHANG`
against a child kept alive by a pipe. It checks the same no-rule, no-context and
target-UID-context controls without reaping the child during measurement. The
rule is removed before final child cleanup. It also requires `disposable_vm=yes`.
Compilation and the default opt-in skip are not runtime admission evidence.

`signal_context_test:debug_target_context` uses real `ptrace(PT_ATTACH)` and
waits for the child's traced stop. It measures the debug admission counter before
removing the rule and detaching, so the separately checked detach cannot inflate
the result. Each control detaches before the next attach. This case requires the
same disposable-VM opt-in and remains unexecuted in a guest.
