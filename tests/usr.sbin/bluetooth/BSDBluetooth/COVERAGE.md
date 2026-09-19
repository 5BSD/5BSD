# Bluetooth test coverage

The Bluetooth tests have one reproducible LLVM coverage entry point:

```sh
tests/usr.sbin/bluetooth/blued/coverage.sh
```

The script builds all ATF programs in an isolated object tree, runs the full
Kyua suite, merges process profiles, and writes both a text summary and a
source-level HTML report under `/tmp/bluetooth-coverage`.  Pass a directory as
the first argument to keep several runs separately.

The report measures production sources linked into the tests.  Test and
third-party sources are excluded.  Hardware cases stay in the run but skip
explicitly when no controller or required privilege is available; software
emulator, fault-injection, parser, state-machine, and integration cases must
run on every developer machine.

## Regression policy

The runner fails when Kyua fails or aggregate production coverage falls below
the checked-in baseline gates:

* line coverage: 95.0%
* branch coverage: 79.8%

It also enforces line and branch floors for the core BLE, ATT, GATT, SMP, and
Mesh components listed in `coverage-baseline.txt`.  These component gates
prevent a well-tested module from masking a regression elsewhere.  Add a
component once it has meaningful direct tests, and raise its floor alongside
material test improvements.

Use `MIN_LINE_COVERAGE` and `MIN_BRANCH_COVERAGE` to trial stricter gates.  Do
not lower the defaults to accommodate a change.  New behavior should include
tests for its successful path, input boundaries, state/error transitions, and
injected dependency failures where applicable.  Prefer deterministic fakes or
the in-process HCI/Mesh emulators over assumptions about host hardware or
kernel configuration.

Only cases in `hci_hw_test` may skip during the coverage run.  Any skip from a
software emulator, parser, state machine, or integration test fails the run,
preventing missing fixtures or host assumptions from silently reducing the
measured surface.

When choosing the next tests, start with the files at the bottom of the HTML
report, then inspect uncovered branches rather than adding cases solely to
increase executed line counts.  Raise the checked-in gates after sustained
improvements leave enough margin for small source-only changes.
