# ZFS loadable module implementation work (2026-11-03)

## Current state

The selected amd64 GENERIC ZFS loadable module is still missing a native producer.
Existing sys/modules/zfs BUILD rules provide headers, while sys/contrib/openzfs
has separate built-in kernel sources. Their compilation policies differ:
loadable objects require KLD_MODULE/KLD_TIED and WITHOUT_NETDUMP. Reusing built-in
objects would not preserve the original module contract.

## Original controls captured

Fresh original Make plain and CTF/debug builds and private installation succeed.
Each uses all sixteen logical CPUs and original source-owned options under the
selected tied kernel context, with null user configuration files. Neither
installs onto the host nor loads the module. Build commands and time/resource
output are retained; these are reference measurements, not native performance
comparisons.

Each build has 261 module compiler objects (254 C and seven assembly) plus one
offset helper. The source Makefile lists five ordinary assembly sources; two
SHA assembly recipes use custom object names. All 262 actual compiler commands
have .meta vectors and .d files. The captured 68,931 consumed occurrences per
profile resolve to 885 unique logical files, including source/generated headers,
with current physical identities and payload hashes. Bindings are captured after
the controls, without claiming a complete pre-build source snapshot. The 35
Makefile input hashes captured before the builds remain unchanged.

Evidence roots:
- /usr/obj/usr/src/bazel-zfs-module-source-facts-r1-20261103/
- /usr/obj/usr/src/bazel-zfs-module-make-references-r1-20261103/

The latter retains actual vectors, consumed inputs, ordered original links,
artifacts, METALOGs, private stages and compiler-inputs-summary.json. Both
controls are terminal and passed. This is original-control evidence only.

## Native work required

- Declare source-owned module compilation and complete original object order.
- Preserve per-source flags, forced compatibility-header order, include namespace
  precedence, SIMD settings, custom SHA object names and CTF policy.
- Reuse existing declared native header/offset producers where their actual
  payload and ABI context match; do not copy original generated outputs.
- Bind declared/consumed inputs and compare actual compiler/link actions and
  plain/CTF artifacts/install manifests against these controls.
- Carry the result through normal build-bsd format-5/backend qualification and
  review whether any helper, input, test or manual interface changes are needed.
- Then refresh the current full kernel and aggregate module build; standalone
  DWARF/source lookup, cross-target, runtime and performance gates remain open.

The module target count stays 728/729 until the missing producer is implemented.
Declaration presence will still not prove aggregate or runtime qualification.
Make stays production/default; BIP remains excluded.
