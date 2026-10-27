# Development checkpoint — 2026-10-27

## Scope and resume point

This checkpoint preserves the accumulated runtime, build/packaging, and native
Bazel work on `dev`. It is not a release qualification. Make remains the
production build path and remains supported for ports. BIP is out of scope.
No host installation, upgrade, or reboot was performed for this checkpoint.

The current component, `sbin/dhclient`, has completed its normal program and
installation comparison against Make. The native graph uses explicit C sources,
headers, dependency ordering, and DTrace generation. The comparison covers 168
defined globals, 11 installation records, seven nonbinary payloads, debuglink,
and DTrace schema and probe sites (allowing relocation of code addresses).
The program was not started against a network.

Evidence is retained under `/usr/obj/usr/src/bazel-dhclient-r2-20261027` and
`/usr/obj/usr/src/bazel-dhclient-make-20261027`. The archive SHA-256 is
`8f211925595878b2c6181110d7b4d6dac6d72752e8ad41a5ed1f189ef57133ef`.
The Bazel README and observability audit contain the detailed component record.
Dhclient tests, static/rescue variants, option coverage, cache/performance
qualification, and live network behavior remain to be completed.

## Remaining migration work

There are 1,058 BUILD.bazel files at this checkpoint; this is a graph-file count,
not a count of successfully qualified products or a completion percentage.
A complete native world, kernel/modules, bootstrap, pkgbase, and image build
has not yet been demonstrated. The current component builds still consume a
Make-prepared SDK. Continue native conversion and artifact/install comparisons,
carry DTrace/FIDL generators and configuration choices into explicit actions,
and maintain the observability audit. Full configuration, sandbox/cache,
runtime, packaging, and CPU/memory/disk performance qualification remain gates.
Build frontend, backend helpers, tests, and documentation must continue to be
updated together whenever their inputs or contracts change.

## Checkpoint checks and limits

- Parsed 415 changed/untracked Python files successfully.
- Shell syntax checks passed for 68 changed/untracked shell files.
- Archive-policy tests: seven passed.
- Component-plan tests: nine passed.
- Tracked-diff whitespace check passed after correcting four trailing-space lines.
- Staging also checked newly added files: cleaned Bazel source whitespace;
  retained significant whitespace in expected-output fixtures, pkg-config
  templates, and patch context. Runtime checkpoint has two harmless EOF
  blank-line warnings.

These checks supplement existing component evidence; they do not establish
runtime correctness of every accumulated change. This commit cleanup did not
rerun the complete regression suite or boot an image.

The original tracked patch, untracked archive, status, and HEAD are saved in
`/usr/obj/usr/src/dev-checkpoint-20261027`. A stray 64-byte ELF fixture at the
source root was moved there as `stray-kernel-fixture`, rather than committed.
Intentional binary and expected-output test fixtures are retained in source.
Private-key markers examined in tests contain malformed dummy input, not keys.
