# Broadcom NVRAM generator qualification

## Scope (2026-11-02)

The next selected Broadcom module inventory contains twelve leaves: bhnd and its
BCMA/SIBA/PCI bridges, plus if_bwi and if_bwn. Their source facts are captured in
/usr/obj/usr/src/bazel-broadcom-module-source-facts-r1-20261102. This inventory is
not compiled module coverage. In particular, the BHND core needs generated C
interfaces and two NVRAM headers; these must have native declared producers.

sys/dev/bhnd/nvram now declares nvram_map_header and nvram_map_data_header using
the existing bsd_device_ids_header rule and the maintained nvram_map_gen.awk
source. The maintained shell wrapper only selects LC_ALL=C, locates that AWK
program, and passes through its arguments. Native actions invoke the same program
with native AWK and explicit C locale, declared input map, and declared execution
runtime. They use no host shell discovery, imported Make-generated files, rewritten
tables, new generator implementation or Make invocation. CcInfo header providers
make these outputs available to future native consumers; the generator package
exports its versioned AWK source to its owning NVRAM package.

## Evidence

Under /usr/obj/usr/src:

- bazel-bhnd-nvram-make-reference-r1-20261102 runs both original Make header targets
  in an isolated object tree using maintained source recipes, no compilation or
  host installation. The two outputs and Make commands/meta remain retained.
- bazel-bhnd-nvram-generator-native-r1-20261102 is a successful normal build-bsd
  format-5 build of both native generators, with immutable output captures and
  actual execution-log evidence. tests=[] runs no registered runtime tests.
- bazel-bhnd-nvram-generator-review-r1-20261102 verifies both complete output bodies
  against Make, apart from exactly one input-path provenance comment. The raw
  outputs/hashes remain retained; no artifacts are rewritten. Both actual actions
  bind the maintained AWK/map input hashes, declared runtime and explicit C locale.

## Frontend review and remaining gates

Existing build-bsd targets/SDK/execution interfaces handle these generators;
there are no new CLI/config, stage, signing, verification or publication policies.
No C frontend, backend helper or manual option change is needed. Actual module
compilation/link/CTF/debug/install comparisons, interface dependencies and optional
BWN PHY selections remain next. No wireless behavior or performance claim follows
from these generator checks. Make remains production/default and BIP is excluded.
