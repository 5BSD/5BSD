# Module ELF export tests and actual loader behavior

## Correction (2026-11-02)

The module provider tests check an explicit ELF export contract. They are not a
simulation of the kernel loader. Earlier Broadcom/HID qualification prose wrongly
called local-only binding findings actual or inevitable load-time failures.
Those claims are withdrawn. Original artifact comparisons, binding inventories
and the explicit source export changes remain valid evidence within their scope.

The source defaults debug.link_elf_obj_leak_locals and debug.link_elf_leak_locals
to true. The ET_REL module loader passes the first setting to lookup_symbol1:
when enabled, local definitions can participate in cross-module name lookup.
The current host read-only observations are retained in
/usr/obj/usr/src/bazel-module-export-contract-review-r1-20261102. No source default,
host sysctl or guest setting was changed. The source history records this fallback
in commit ecd8245e0d7 (2021), following the separation of debug/local symbol lookup.
See sys/kern/link_elf_obj.c and sys/kern/link_elf.c for the actual loader contracts.

Consequently, an original localized callback may resolve under the default loader.
Explicit public exports remove reliance on that compatibility fallback; they do
not prove that the original module failed to load. The hgame callbacks are declared
public functions used by explicitly dependent controllers. Its three-name export
list makes that API explicit. The Broadcom shared bus providers similarly retain
explicit exports. No additional runtime authority, security restriction or loader
behavior is introduced by those Make/native source policies.

## What the tests establish

The module_providers tests classify actual ELF definitions with global/weak
bindings and reject strong cross-module imports whose supplied definition is
only local. Required-edge assertions exercise named public API boundaries.
The negative fixtures intentionally localize real provider artifacts and must
fail that explicit export contract. They are not evidence of a default-loader
rejection. Imports without supplied providers are reported separately.

The static closure observer additionally checks strong symbol names against a
qualified kernel artifact and a supplied module cohort. This is neither complete
module dependency metadata validation nor runtime ABI or loader emulation. In
particular, strict ET_REL lookup distinguishes STB_GLOBAL from other bindings;
the generic ELF test's global/weak classification does not by itself qualify
running with either leak_locals setting disabled.

## Qualification still required

VM loader tests must record both guest leak_locals settings, actual kernel/config
identity, module dependencies, built-in providers and load/unload results. Default
compatibility behavior and disabled-fallback behavior require separate evidence.
Built-ins can mask dependencies; static symbol-name coverage cannot replace these
tests. Probe registration, live events, device behavior and performance remain
separate gates. No host module loading or installation was performed.

The existing build-bsd format-5 interface remains sufficient. This correction
updates test descriptions and maintained qualification/roadmap documentation;
it does not change build inputs, signing, staging, publication or kernel policy.
