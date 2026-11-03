# Module declaration inventory correction (2026-11-03)

## Defect and correction

A BUILD file can contain only headers. Directory presence therefore failed to
identify the missing ZFS loadable module, even though separate OpenZFS built-in
kernel objects exist. The earlier generic-macro regular expression also omitted
firmware module producers and could match comments or unrelated module names.

module_inventory.py now parses BUILD syntax as data without executing it. It
counts literal top-level module calls whose module name equals the selected
Make KMOD and whose producer is loaded from the maintained generic or firmware
module helper. Loaded aliases are recognized. Headers, comments, string content,
unrelated module names and identically named helpers from unrelated files do
not count. Parse failures make the audit incomplete rather than contributing
coverage. No per-module exception list or copied inventory is introduced.

Format 3 retains the generic-only direct_module_macro fields and adds explicit
amd64_module_declarations plus selected_with/without_amd64_module_declaration.
These are source declaration counts. They do not resolve arbitrary Starlark
expressions, prove configured target analysis, cover cross-architecture macros,
or prove successful builds/loading. Unsupported declaration forms remain gaps.
Complete means the Make traversal completed without inventory errors, not that
the modules or migration are complete.

## Verification

Twelve unit tests pass directly, including real BSD Make parent-export/source
context tests and the header-only, commented, wrong-name, loaded-alias, unrelated
helper and malformed-source regressions. The registered Bazel target
//tools/build/bazel:module_inventory_test also passes through the maintained
format-5 backend, with one reported target and no reported skips.

A fresh recursive original Make inventory with all sixteen query workers finds
729 selected amd64 GENERIC leaves and 729 BUILD files, but only 728 recognized
module producers: 690 generic and 38 firmware. ZFS is the sole missing producer.

Evidence:
- /usr/obj/usr/src/bazel-current-module-declarations-20261103/amd64.json
- /usr/obj/usr/src/bazel-module-inventory-test-r1-20261103/receipt.json
- /usr/obj/usr/src/bazel-module-inventory-test-r1-20261103-inputs/inputs.json

This changes audit reporting only. No build-bsd input, backend build contract,
installation, signing, security policy or publication behavior changes; no
frontend-C or manual interface update is required. Make remains the production
default. BIP stays excluded.
