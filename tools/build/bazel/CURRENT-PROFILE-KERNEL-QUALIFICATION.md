# Current-profile AMD64 full kernel refresh (2026-11-06)

The normal maintained build-bsd bazel-test workflow passes the full AMD64 GENERIC
link, CTF merge and runtime/debug split for committed source a18c2ecd1ec with the
new shared TCP_HHOOK override. It uses all 16 CPUs, the explicit current package
SDK, TESTS=false, production malloc, CTF=true and kernel_debug=true. This is native
construction qualification; no runtime or installation claim follows from it.

## Evidence

All evidence paths are under /usr/obj/usr/src:

- bazel-kernel-current-profile-request-r1-20261106/inputs.json: explicit inputs.
- bazel-kernel-current-profile-native-r1-20261106: passed receipt, compact execution
  log, stdout/stderr and immutable captures for kernel.linked, kernel.full, kernel,
  kernel.debug and the generated configuration tree/override.
- bazel-kernel-current-profile-review-r1-20261106/{audit.py,review.json}: independent
  receipt/manifest/content verification, actual ELF runtime/debug CRC validation,
  explicit TCP_HHOOK header/override and native parser inventory identity checks.

Bazel reports 258.848 seconds, 4,146 action cache hits, one disk-cache hit and
5,298 processwrapper-sandbox executions. These are build-log observations, not a
controlled Make performance comparison or proof that the sandbox denies every
undeclared dependency. The time -l resident-memory number belongs to the client;
it is not a measurement of the Bazel server and all compiler children.
The parser inventory selects 2455 objects; startup/backend objects are separate.
No tests were requested in this full-kernel build; the separately recorded TCP
cohort has 14 test targets per profile. Earlier controlled full-kernel Make parity
retains its old input scope and is not rebound to this refresh.

Receipt SHA256: 45904fafa71b2135898815acaac118b7a7a0d971dabf68b24ecaa1de549378f5
Review SHA256: 2f916a7de31a3c0c7a56bae6d3040c0c1762309e770025eebfe048abf3baf73e

## Remaining gates

Complete root module selection, optional native producers, coherent kernel/GDB/
module/directory/alias/linker.hints installation and pkgbase composition remain.
A refreshed independent Make comparison, normal boot/login/PAM/SSH/capability
services, real version upgrades, ARM64/RISC-V, bootstrap/cache/reproducibility/
sandbox/debug/resource/hardware and combined publication qualification remain.
Make remains production/default; BIP is excluded. No host installation, module
load, upgrade or reboot was performed. Existing frontend APIs suffice; this
refresh changes evidence and documentation, not signing/publication policy.
