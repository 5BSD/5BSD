# traceroute and traceroute6 native candidates

2026-11-01. Make remains the production backend. These are native component
build/install candidates; full world/kernel/pkgbase and privileged network
runtime qualification remain open.

Both programs use direct rules_cc cc_binary source ownership. IPv6 consumes the
existing IPv4 as.c/as.h through narrow exports. Source and dependency order
match maintained Make. The initial IPv6 declaration had a different explicit
order; the comparison caught the resulting layout and DT_NEEDED order
changes. Correcting the declaration preserves native linking, with no binary
rewriting. The original comparison remains in the first parity directory.

The native component-local setting `//usr.sbin/traceroute:ipsec` defaults true.
Setting it false represents Make's presence-only TRACEROUTE_NO_IPSEC selector,
removing the IPv4 IPSEC definition and library dependency. IPv6 retains its
maintained unconditional IPsec behavior. Existing typed tests and Casper
settings are reused. Casper stays enabled, consistent with required source
policy; disabling it is not qualified here. New component constraints are
FreeBSD OS only; existing library/SDK coverage still limits the evidence to
amd64.

Installation preserves /usr/sbin, root:wheel logical mode `4555`, separate debug
files, section 8 manuals, runtime package ownership and the complete maintained
IPv4 ATF wrapper/Kyuafile. Its VNET/raw-socket jail metadata is byte-identical to
Make. The installed script also needs the existing shared
`//tests/sys/common:install_archive` vnet.subr support in the complete test
product; it is not copied into a private replacement. No network case or
privileged/setuid behavior was exercised. No host network/service configuration,
installation, upgrade, VM start or reboot occurred.

## Comparison evidence

Maintained build-bsd format 5 runs:

- `/usr/obj/usr/src/bazel-traceroute-pair-qualification-r2-20261101/`
- `/usr/obj/usr/src/bazel-traceroute-noipsec-qualification-20261101/`

Independent maintained Make references:

- `/usr/obj/usr/src/bazel-traceroute-make-20261101/`
- `/usr/obj/usr/src/bazel-traceroute6-make-20261101/`
- `/usr/obj/usr/src/bazel-traceroute-noipsec-make-20261101/`

Reports are in `bazel-traceroute-pair-parity-r2-20261101` and
`bazel-traceroute-noipsec-parity-20261101` under /usr/obj/usr/src. All default
IPv4 eight, IPv6 five, and no-IPsec/tests-disabled IPv4 five installation records
match Make destinations/types/owners/groups/modes/pkgbase tags. All manuals,
installed scripts and Kyuafile match bytes. Logical NO_ROOT metadata is verified;
this does not establish actual privileged execution or installed owner policy.

In all three configurations, every installed executable ELF section matches
Make except .gnu_debuglink. Dynamic dependency order, imported/exported symbols
and checked ELF hardening match. Debuglink names and CRCs validate against each
actual separate debug file. Whole DWARF/debug-file identity and debugger source
resolution remain unqualified. Neither executable has a direct DOF section,
matching Make. Existing native Casper/cap_dns shared-library instrumentation is
preserved; live tracing and program-level audit coverage remain review items
for these setuid network tools.

Default IPv4 artifacts return to the same hashes after the no-IPsec variant,
whose executable differs and whose imports/dependencies match its Make
reference. `bazel-traceroute-review-20261101/configuration-restoration.json`
records this bounded output-selection/restoration check. Source mutation,
remote-cache and unchanged zero-action reuse are not qualified by this check.

## Independent Make oracle input

The temporary install-reference.py comparison helper now accepts repeated
`--make-define NAME` selectors. Each name must be an uppercase identifier in the
selected component basename namespace, e.g. TRACEROUTE_NO_IPSEC. Values are
always exactly `1`. Arbitrary assignments/expansions, protected global compiler,
target/path/staging/profile names, duplicates and option/profile collisions
are rejected. Baseline SDK/profile checks remain, and a definition run rechecks
compiler/target/object identity before building. Receipts record definitions,
complete commands and the new validation module's hash. This is a temporary
independent oracle interface, not production graph interpretation of Make.

The actual no-IPsec reference passes with its recorded selector and final input
rechecks. Six focused validation cases also executed and passed through native
`//tools/build/bazel:install_reference_options_test` in the no-IPsec frontend
run. The existing format 5 frontend already passes typed source labels, so no new
build-bsd argument or backend/signing/publication/manual contract is required.

The comparison scripts/inputs are retained in
`/usr/obj/usr/src/bazel-traceroute-review-20261101/`. Runtime VNET routing,
raw-socket/Capsicum/setuid behavior, live probes/audit, other architectures,
independent bootstrap, complete package publication and comparative CPU/memory/
disk performance remain open. BIP remains out of scope.
