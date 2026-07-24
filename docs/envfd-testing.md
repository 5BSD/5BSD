# EnvFD Testing Guide

This guide covers build-time validation, installation, automated tests, manual
smoke tests, observability, and rollback for EnvFD.

EnvFD changes span the kernel syscall and file-descriptor implementation,
libc, public headers, kqueue, Capsicum descriptor propagation, process
inspection tools, DTrace, and audit conversion. A newly built test program is
not sufficient by itself: behavioral tests must run on the matching new
kernel and userland.

## What is being tested

The main invariants are:

- A value is published atomically and read as one complete snapshot.
- A failed write does not change the value or generation.
- `ENVFD_WRITE_ONCE` seals the shared object, including through `dup()`,
  `fork()`, and `SCM_RIGHTS`.
- Capsicum read, write, ioctl, event, and stat rights are enforced.
- `ENVFD_CAPMODE_ONLY` rejects operations outside capability mode.
- `EVFILT_ENVFD` reports successful writes and sealing, with generation and
  value size.
- Descriptor flags and `CAP_XFER_*`, `CAP_CLOEXEC_*`, and `CAP_CLOFORK_*`
  propagation states are installed and enforced.
- Resource charges survive descriptor duplication and disappear after the
  final reference closes.
- `procstat`, `fstat`, `kinfo_file`, DTrace, and audit paths understand the
  descriptor without exposing its value.

## 1. Preserve a bootable system

Before installing a development kernel, ensure that `/boot/kernel.old` is
usable or create a ZFS boot environment:

```sh
doas bectl create before-envfd
```

Keep console access available for the first reboot. Do not remove
`/boot/kernel.old` until testing is complete.

## 2. Build

From a clean shell using this source tree:

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld buildkernel KERNCONF=GENERIC
```

Use the intended custom `KERNCONF` instead of `GENERIC` when appropriate.
The full world build is recommended because EnvFD adds libc and libsys
interfaces, public ABI definitions, process-inspection support, tests, and a
DTrace script.

Useful source-only checks that do not require rebooting include:

```sh
cd /usr/src
git diff --check
mandoc -Tlint lib/libsys/envfd.2
mandoc -Tlint lib/libprocstat/libprocstat.3
dtrace -e -s share/dtrace/envfd-events
```

The `-e` option exits after compiling the DTrace request. Use the installed
script after reboot for runtime tracing.

## 3. Install and reboot

Follow the normal FreeBSD source-upgrade procedure for the machine. A typical
development sequence is:

```sh
cd /usr/src
doas make installkernel KERNCONF=GENERIC
doas shutdown -r now
```

After the machine boots the new kernel:

```sh
cd /usr/src
doas make installworld
doas make -C tests/sys/kern install
```

Installing world is important. Running the new tests with an old libc or old
headers can produce misleading failures even when the kernel is correct.

## 4. Confirm the matching system is active

The EnvFD sysctl tree proves that the running kernel contains the
implementation:

```sh
sysctl kern.envfd
```

Expected nodes include:

```text
kern.envfd.max_objects
kern.envfd.max_bytes
kern.envfd.max_user_objects
kern.envfd.max_user_bytes
kern.envfd.max_value_size
kern.envfd.objects
kern.envfd.bytes
```

Confirm the library interface, manual page, test, and DTrace script are
installed:

```sh
man 2 envfd_create
test -x /usr/tests/sys/kern/envfd_test
test -r /usr/share/dtrace/envfd-events
```

If `sysctl kern.envfd` reports an unknown OID, the new kernel is not running.
If `envfd_create()` returns `ENOSYS`, kernel and userland are mismatched.

## 5. Run the automated tests

List the installed cases:

```sh
kyua list -k /usr/tests/Kyuafile | grep envfd_test
```

Run the suite without allowing global sysctl changes:

```sh
kyua test -k /usr/tests/Kyuafile sys/kern/envfd_test
kyua report
```

Fourteen cases should pass. `accounting_limits` should be skipped because it
requires root and the `allow_sysctl_side_effects` configuration variable.

Run all fifteen cases, including temporary enforcement of the global object
and byte limits:

```sh
doas kyua \
    -v test_suites.FreeBSD.allow_sysctl_side_effects=true \
    test -k /usr/tests/Kyuafile \
    sys/kern/envfd_test
doas kyua report
```

The test program is marked exclusive, so Kyua should not run it concurrently
with other tests that could perturb global EnvFD accounting.

Run one case while debugging:

```sh
kyua test -k /usr/tests/Kyuafile \
    sys/kern/envfd_test:vectored_io
kyua report
```

Replace `vectored_io` with any case from the following table.

| Test case | Main coverage |
| --- | --- |
| `basic_value_semantics` | Unwritten, binary, empty, replacement, generation, complete reads |
| `validation_and_access` | ABI validation, names, limits, and read/write access modes |
| `vectored_io` | `readv()`/`writev()`, undersized reads, and late-copy fault atomicity |
| `concurrent_snapshots` | Readers never observe torn concurrent replacements |
| `write_once_shared_and_atomic` | One winning writer and permanent object-wide sealing |
| `write_once_pass_and_fork` | Sealing through `SCM_RIGHTS`, duplicated references, and fork |
| `kqueue_notifications` | Future-only delivery, coalescing, filters, deletion, write, and seal events |
| `capsicum_rights` | `CAP_READ`, `CAP_WRITE`, `CAP_IOCTL`, `CAP_EVENT`, and ioctl allowlisting |
| `capmode_only` | Operations rejected outside and accepted inside capability mode |
| `create_in_capmode` | Creation and use after entering Capsicum capability mode |
| `initial_descriptor_confinement` | Initial close flags and transfer/fork/exec propagation states |
| `unsupported_operations` | Poll semantics and rejection of seek, mmap, truncate, and AIO |
| `kinfo_metadata` | `kern.proc.filedesc` type, state, name, size, flags, and generation |
| `accounting_limits` | System object and byte limit enforcement and failure rollback |
| `accounting_lifecycle` | Charges across replacement, `dup()`, and final close |

On failure, preserve the result database and obtain verbose context:

```sh
kyua report --verbose
kyua report-html --output /tmp/envfd-kyua-report
```

Also capture:

```sh
uname -a
sysctl kern.envfd
sysctl kern.features.security_capabilities
```

## 6. Manual API smoke test

Create `/tmp/envfd-smoke.c`:

```c
#include <sys/envfd.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
	struct envfd_create_options options =
	    ENVFD_CREATE_OPTIONS_INITIALIZER(32);
	struct envfd_info info;
	char value[32];
	ssize_t n;
	int fd;

	options.eco_flags = ENVFD_WRITE_ONCE;
	fd = envfd_create("smoke.secret", &options);
	if (fd == -1) {
		perror("envfd_create");
		return (1);
	}
	if (write(fd, "hello", 5) != 5) {
		perror("write");
		return (2);
	}
	memset(&info, 0, sizeof(info));
	if (ioctl(fd, ENVFD_GETINFO, &info) == -1) {
		perror("ENVFD_GETINFO");
		return (3);
	}
	n = read(fd, value, sizeof(value));
	if (n != 5 || memcmp(value, "hello", 5) != 0) {
		fprintf(stderr, "snapshot mismatch\n");
		return (4);
	}
	errno = 0;
	if (write(fd, "again", 5) != -1 || errno != EROFS) {
		fprintf(stderr, "object was not sealed\n");
		return (5);
	}
	printf("name=%s generation=%ju size=%ju state=%u\n",
	    info.ei_name, (uintmax_t)info.ei_generation,
	    (uintmax_t)info.ei_value_size, info.ei_state);
	close(fd);
	return (0);
}
```

Compile and run it against the installed interface:

```sh
cc -Wall -Wextra -Werror -o /tmp/envfd-smoke /tmp/envfd-smoke.c
/tmp/envfd-smoke
```

Expected output contains generation `1`, size `5`, and
`ENVFD_STATE_SEALED`'s numeric value:

```text
name=smoke.secret generation=1 size=5 state=2
```

## 7. Inspect a live descriptor

For process-tool testing, temporarily add `sleep(30);` before `close(fd);` in
the smoke program. Start it in one terminal and use its PID in another:

```sh
procstat -f PID
fstat -p PID
```

Expected results:

- `procstat` identifies the descriptor type as `envfd`.
- `fstat` includes `[envfd]`.
- Kernel file metadata exposes the immutable descriptive name and state.
- Neither tool prints the stored bytes.

The automated `kinfo_metadata` case performs a stricter check against
`kern.proc.filedesc`.

## 8. Observe DTrace events

First confirm that the probes exist:

```sh
doas dtrace -l -P envfd
```

Trace lifecycle activity in one terminal:

```sh
doas dtrace -s /usr/share/dtrace/envfd-events
```

Run `/tmp/envfd-smoke` or the test suite in another terminal. Expected events
include `CREATE`, `write`, `KQUEUE-NOTIFY`, `SEAL`, `read`, and `CLOSE`,
depending on the workload.

The trace must not contain the EnvFD name or stored value. It reports object
addresses, process and credential metadata, generations, sizes, flags,
notifications, and errors.

Stop tracing with `Ctrl-C`.

## 9. Check accounting manually

Record a baseline:

```sh
sysctl kern.envfd.objects kern.envfd.bytes
```

Run the sleeping smoke program and query the counters again. Both counters
should increase while the descriptor is alive and return exactly to baseline
after it exits.

Do not casually change the limit sysctls on a shared system. The
`accounting_limits` ATF case saves the original values, runs exclusively,
checks failed-creation rollback, and restores the values in cleanup.

If a test is interrupted while changing limits, inspect and restore:

```sh
sysctl kern.envfd.max_objects
sysctl kern.envfd.max_bytes
```

Use the values recorded before the test. Setting either value to zero means
unlimited and is not a neutral reset.

## 10. Stress and repetition

Repeat the race-sensitive cases:

```sh
i=0
while [ "$i" -lt 100 ]; do
	kyua test -k /usr/tests/Kyuafile \
	    sys/kern/envfd_test:concurrent_snapshots \
	    sys/kern/envfd_test:write_once_shared_and_atomic || exit 1
	i=$((i + 1))
done
```

Check for leaked accounting afterward:

```sh
sysctl kern.envfd.objects kern.envfd.bytes
```

The values must match the pre-loop baseline once all test processes exit.
Run the loop on diagnostic kernels such as `INVARIANTS`, `WITNESS`, and
`DEBUG_MEMGUARD` when available; these configurations provide more value
than simply increasing the iteration count on a production-style kernel.

## 11. Audit integration

`__specialfd` uses the `AUE_SPECIALFD` event. On a machine where audit is
already enabled and that event is selected by policy, create an EnvFD and
inspect the resulting BSM record with the normal site audit tooling.

Verify that conversion succeeds and records the special-descriptor type,
flags, and numeric creation value. The record must not contain the EnvFD
name or its stored bytes.

Do not change a production machine's audit policy solely for this smoke test.
The kernel build validates the BSM conversion switch; runtime audit testing is
best performed in a disposable boot environment or VM with an existing audit
configuration.

## 12. Failure interpretation

Common failure signatures:

| Symptom | Likely cause |
| --- | --- |
| `sysctl: unknown oid 'kern.envfd'` | Old kernel is still running |
| `envfd_create: Function not implemented` | New libc with an old kernel |
| Missing `envfd_create(2)` manual page | Userland or manuals were not installed |
| Kyua cannot find `envfd_test` | Tests were not built or installed |
| `accounting_limits` is skipped | Expected unless run as root with the Kyua variable |
| Persistent nonzero accounting delta | Live reference, failed cleanup, or kernel leak |
| No DTrace probes | Kernel lacks DTrace support or the old kernel is running |
| `ECAPMODE` from a capmode-only object | Caller has not entered Capsicum capability mode |
| `EMSGSIZE` on read | Buffer is smaller than the current complete snapshot |
| `EROFS` on write | A write-once object has already been successfully written |

## 13. Rollback

If the new kernel does not boot, select `kernel.old` from the loader. From a
working system, schedule the previous kernel for the next boot with:

```sh
doas nextboot -k kernel.old
doas shutdown -r now
```

If a boot environment was created, activate it according to the local
`bectl(8)` recovery procedure. Preserve the failed kernel, test output,
`sysctl kern.envfd` output, and any panic dump until the problem is
understood.
