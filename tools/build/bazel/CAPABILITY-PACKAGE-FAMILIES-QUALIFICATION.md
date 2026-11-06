# Additional capability package-family metadata

## Scope (2026-11-06)

The explicit `//packages:capability_family_manifests` aggregate adds nineteen
source-owned family declarations to the five initial core families. Names:

capsule, capsulectl, switchboard, switchboardctl, oes, bsdaudit, bsdcrypto, bsddevice, bsdnetwork, bsdnotify, bsdmemory, libcapsulert, libcapability, libcapbundle, libchannel, libservice, libucl, libshmring, libauditcmp.

This is metadata coverage for the named families, not all capability packages,
all world package buckets, payload/archive creation or installed service testing.
Existing per-component package_layout/package_manifests/packages targets remain
separate; their earlier identity constants and payload selection are not changed
or qualified by these new family targets. Whole-world creation must consume the
source-owned family providers and reconcile them with the full world inventory.

The new declarations preserve source templates, overrides, subpackage choices,
sets, license logic and explicit base/development dependency edges. Shared UCL
exports have narrow package visibility. No C, kernel, runtime authentication or
service code changes are included. No production Makefile parser was introduced.

## Declared input fix

The first alternate native build failed in the process-wrapper sandbox for
bsdcrypto. With debug disabled, only the base override was selected; that override
includes the default shared template, which had no direct selected subpackage
consumer and therefore was omitted from action inputs. The generic family rule
now always declares its default template alongside selected overrides. Additional
nested includes still require explicit template_inputs. The final alternate
capture constructs these base-only families with their includes present. No
sandbox weakening, source template rewriting, host-path fallback or test omission
was used. The initial default analysis failure was a duplicate existing libchannel
export; the duplicate was removed and existing narrow visibility preserved.

## Independent controls

Both final native captures pass through maintained build-bsd bazel-test with
16 jobs and the real source-settings test. Original Make buildenv commands produce
only explicit .pkgucl metadata targets into isolated objects. Every selected
package name and effective MK option is queried; missing and extra native
manifests fail. Both UCL results are decoded with the same SDK flua/libucl and
entire objects compared, including package scripts, deps, annotations, sets,
licenses, descriptions and family suffix semantics. Include/source hashes and
baseline environment verification bind the original controls. Results:

- Default (tests off, split manuals off, debug on, LLVM binutils on): all 47 match.
- Alternate (tests on, split manuals on, debug off, LLVM binutils off, OrgBSD
  prefix and explicit alternative maintainer/website): all 45 match.

No raw UCL byte identity is claimed. The static SDK interpreter is still a
Make-built bootstrap input. These controls do not establish complete global
DEBUG_FILES payload support, bootstrap, sandbox isolation strength, installed
services, normal authentication, upgrades, publication or performance.

## Evidence

All paths below are relative to /usr/obj/usr/src. audit.py, original commands,
input hashes, decoded objects and immutable native artifact bindings are retained
with the review. The failed default-r1/alternate-r1 captures are retained.

- bazel-capability-package-families-default-native-r3-20261106/receipt.json
  SHA256 4482ad98bf052e6afc81ab1e518af7553bfc9ad211f573b2094e4230cc48925f
- bazel-capability-package-families-alternate-native-r2-20261106/receipt.json
  SHA256 580a58b75df8a560db0152c9129ecad02b603f28c991ff5a23e10397b9e96578
- bazel-capability-family-make-review-r1-20261106/review.json
  SHA256 95642ae9182f2f738b690fe3ffa4014105e911b1b8e20aaf400da2825b199565

Input requests: bazel-capability-package-families-default-request-r1-20261106 and
bazel-capability-package-families-alternate-request-r1-20261106 (inputs.json).

## Frontend and next work

Existing format-5 target/build-setting inputs select the new aggregate; no C CLI,
backend dispatch, stage/signing/verification or publication interface changes are
required. The maintained manual is updated in this change. Keep Make default.
Continue remaining family declarations (including libfidl's optional SDK tools
and explicit target ports versions), reconcile exact full-world metadata coverage,
then construct actual whole-world packages and qualify installed systems/upgrades.
All world/kernel/modules/debug/cross/bootstrap/cache/sandbox/reproducibility,
CPU/RAM/disk I/O/footprint/runtime and combined-publication gates remain open.
BIP remains excluded; no host installation, upgrade or reboot was performed.
