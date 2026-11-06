# Correct pkg rootless-mode interface — 2026-11-06

Pkg 2.9 reads `INSTALL_AS_USER` from the process environment; `-o INSTALL_AS_USER`
is not that interface. The new complete-image qualification exposed the error in
existing release helpers. Callers now export the environment explicitly:

* release VM pkgbase and cache cleanup;
* DVD pkg staging;
* hardware catalogue authentication/fetch and live firmware install;
* private jailed database registration;
* real-package hardware test installation/upgrade commands.

Database/cache/repository isolation, script/trigger/plugin suppression, signature
verification, kernel/hardware identity and publication advancement checks remain
in force. This is not a new build policy or an authorization to install the host.
Python callers preserve their existing explicit environment and add this variable;
shell command strings use `env` so expansion cannot treat an assignment as a command.

`/usr/obj/usr/src/bazel-rootless-pkg-helpers-review-r1-20261106/review.json` records
source/tool hashes, UID and exact checks. The actual hardware suite runs 45 tests:
44 pass, one requires an explicit module. That case passes separately with
`HARDWARE_TEST_MODULE=/boot/modules/i915kms.ko`. These tests use private package
repositories and target/media roots; they do not install hardware on the host.
They exercise authenticated catalogue/fetch failures, ABI-matched upgrade and
firmware installation, plus preserving the existing hints index on failure.
The release command receiver test verifies the environment reaching its child;
shell syntax and changed Python parsing also pass.

This does not rerun privileged jailed database registration, full release media,
real hardware driver loading or a full-system boot-environment upgrade. Existing
build-bsd backend actions invoke these maintained helpers; no new frontend flag,
C interface or production/default change is required. Make stays default.
