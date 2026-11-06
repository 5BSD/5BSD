# Complete pkgbase installation VM qualification (2026-11-06)

## Maintained suite and scope

world-pkg-install-fixture.py consumes immutable qualification outputs and an
explicit plan. It uses every source installation archive and the actual complete
package index/catalogue, not a selected executable list. The plan selects pkg,
makefs, source OSVERSION, epoch, command_timeout_seconds, disk sizes, kernel/bootstrap inputs and site-state
fixtures. All source archive paths are checked before extraction. Named source
accounts determine filesystem UID/GID; host account ownership is never substituted.
The assembler requires a new standard /usr/obj/usr/src output directory and runs
unprivileged. It records commands, hashes and immutable artifact bindings.

The target is a 4GB disk-backed UFS filesystem containing the complete native
bootstrap world and an initially empty package database. A separate 1GB read-only
input disk supplies all packages and the unsigned private test catalogue. The
existing VM runner supplies a separate disk-backed bootstrap root, 2GB guest RAM,
four TCG vCPUs and no network. Nothing loads the whole target image into RAM.
This is an installation test, not a proposed production image layout or installer.

The source-built native ATF driver in tests/world_pkg_vm requires root inside a
VM, mounts declared input/output devices, and starts the Python checker. Every
pkg operation executes after os.chroot into the target with native target library
and account lookup. It enables real package scripts and disables plugins, syslog
and automatic repository updates. It installs the complete selected set, checks
exact installed names, contents, UID/GID/modes/flags/symlinks, physical directories,
package-local hardlink equivalence and pkg checksums. It then creates explicit
site config, account and data modifications and force reinstalls the same package
versions. The second check requires those local modifications/data to survive and
native pw to resolve the new account. Construction files must retain their expected
owners and modes. The driver emits the checker report and checks cleanup unmounts.

## Initial prepared evidence and failed whole-case timeout

Paths are relative to /usr/obj/usr/src:

- bazel-world-pkg-layout-native-r4-20261106 passes eleven test targets and builds
  the native static ATF driver, all 445 packages and complete source corpus.
- bazel-world-pkg-install-fixture-r3-20261106/fixture.json has status prepared:
  445 packages, 32,512 payload paths and 1,369 merged physical directories.
  This is preparation evidence, not installation proof.
- Its target.ufs SHA256 is
  39f3fc193d5f8213926c449ea7b176484fb3ddb10f603887bcdebc4bf541b9a7.
  Its input.ufs SHA256 is
  5cadae8b2a9b7009115d6aa116087c12bcd5589758dfa42b705a6f91f4630f7d.
- bazel-world-pkg-vm-request-r2-20261106/fixture-plan.json declares all fixture
  inputs. fixture-r3/vm-command.json records the exact runner invocation.
- bazel-world-pkg-install-vm-r2-20261106 is the failed retry. Its serial.log,
  host-resources.jsonl and result.json contain the authoritative result.
  QEMU is subject to a 3GB host RSS ceiling and an 1,800-second outer deadline.
  This attempt failed its 900-second whole-case deadline during reinstall. Resource snapshots are
  observations, not controlled I/O or Make performance acceptance.

The first VM attempt (install-vm-r1) failed before package installation: native
world composition omitted /dev. The source-derived distrib-dirs implementation
fixes the actual backend, rather than creating a fixture-only /dev. That run also
failed an existing service deadline assertion under host load. The current retry
passes that unchanged baseline assertion; no latency assertion was relaxed.
Earlier assembly failures and intermediate prepared fixtures are retained. Only
failed assembly scratch copies were cleaned, with cleanup records preserved.

## Reproduce

Build the driver, complete world targets and tests through the maintained format-5
build-bsd bazel-test workflow. Then use the maintained assembler:

```sh
/usr/local/bin/python3.12 /usr/src/tools/build/bazel/world-pkg-install-fixture.py \
  --qualification /usr/obj/usr/src/bazel-world-pkg-layout-native-r4-20261106 \
  --plan /usr/obj/usr/src/bazel-world-pkg-vm-request-r2-20261106/fixture-plan.json \
  --output /usr/obj/usr/src/NEW-fixture
```

Use the existing tools/test/daemon-runtime/run-vm.py runner with the generated
bootstrap tree, source/input disk hashes, a fresh work directory and the desired
explicit resource limits; the retained vm-command.json is the exact tested model.
Changing inputs requires new output directories and fresh hashes, not reuse of an
old passing receipt. No host mount, host package installation or publication occurs.

## Frontend and remaining gates

The normal format-5 frontend builds the native driver and captures all artifacts.
The maintained assembler/runner are qualification helpers, not alternative system
build/publication frontends. The existing runtime bootstrap assembler now stages
an outer chroot executable only if requested; this checker uses os.chroot instead.
Its existing boundary tests pass. No C CLI, production Make default or signing
contract changes are needed. Hardware and combined publication remain separate.

The initial r2 retry is terminal FAIL at the case deadline. Its saved interrupted
report proves the first installation phase and subsequent checksum check, but no
reinstall result. The corrected acquired-reaper harness passes real escaped-session
positive/negative tests. A fresh fixture-r4 and install-vm-r3 retry use explicit
command_timeout_seconds=900, whole-case budget 1800 and outer deadline 2100;
phase output and timeout logs are retained. See
[RUNTIME-REAPER-QUALIFICATION.md](RUNTIME-REAPER-QUALIFICATION.md).
Final installation/reinstallation acceptance remains pending. Even a pass would
not establish a new-version upgrade, actual database schema compatibility, normal
Capsule PID1 startup, login/PAM/SSH/service operation, native Bazel kernel boot,
Secure Boot, verified boot or compromised-root protection. The fixture kernel is
an explicitly selected matching Make-built GENERIC-NODEBUG kernel. Those complete
system, architecture, bootstrap/cache/sandbox/reproducibility and performance gates
remain required. BIP remains out of scope.
