# Native selected APM utility (2026-11-02)

## Scope and maintained policy

The fresh 2,127-directory configured world inventory selects usr.sbin/apm through
usr.sbin/Makefile.amd64 under MK_APM. It previously lacked a native producer.
The explicit leaf Makefile builds apm regardless of that parent switch; the
native leaf follows that behavior. Whole-world parent aggregation must preserve
MK_APM selection rather than inventing a leaf-only configuration gate.

A source-owned cc_binary compiles the original apm.c with Make's actual WARNS=6,
PIC/PIE and SSP policy and the existing declared compiler/sysroot. Installation
uses the maintained utility helper for /usr/sbin/apm, its debug file and apm.8,
with package=apm. No original C code, power policy, device access or capability
authority changed. The x86_64 native profile is qualified; the Make-supported
i386 target is not qualified here, and ARM/RISC-V parents do not select APM.

The existing build-bsd format-5 target/settings API directly builds apm,
install_archive and safe_cli_test. No new CLI, backend, security, signing or
staging input is required. Make remains production/default. Final package
creation and world selection composition are separate gates.

## Evidence under /usr/obj/usr/src

- bazel-apm-parent-context-r1-20261102 records actual .MAKE.EXPORTED propagation
  from root through usr.sbin to apm. The selected source/flags/library/package/
  install fields match the standalone leaf in this explicit configuration.
  This does not establish correctness of every world parent's export context.
- bazel-apm-make-r1-20261102 builds with all sixteen CPUs and stages an independent
  maintained Make reference. make-meta-r1 uses supported metadata mode and proves
  original object/linked bytes unchanged while recording actual recipes and
  all 41 physical prerequisites. No host installation occurred.
- bazel-apm-native-qualification-r1-20261102 passes the normal frontend with
  sixteen jobs and compact logging. The 18 GiB start/16 GiB reserve guard did not
  fire. No default execution-log or production compiler-helper policy changed.
- bazel-apm-audit-r1-20261102/report.json binds immutable candidate output and the
  actual compiler output digest. The single source retains exact raw text,
  both constant sections and all five raw non-debug relocation sections.
  Ordered macro/warning vectors and all 41 declared prerequisite hashes match.
  Read-only inspection preserves the input/reference/candidate hashes.
- Strict ELF comparison accepts interpreter, PIE, hardening, imported/exported
  symbols/versions and ordered NEEDED (libc.so.7). Linked sections match except
  .debug_abbrev, .debug_aranges, .debug_info, .debug_line, .debug_loc, .debug_ranges
  and .debug_str. Final debug bytes/full ABI equivalence are not claimed.
- All five Make installation records match owner/group/mode/package tags and
  tar metadata; decompressed manual content and both debug-link CRCs validate.
  The package archive was not installed or published.
- One retained Python wrapper contains three actual passing methods. Two test
  invalid single options (-h and -?) whose original source exits from usage()
  before open(APMDEV). The third uses rtld's trace mode before main to verify
  declared native library paths. The same three authored checks pass against
  the fresh Make program (make-safe-cli-r1 log). No test opens /dev/apm, issues
  power ioctls or changes the host's state.
- Compact evidence is streamed by the original Bazel converter with all 189
  tool bindings checked before/after; no expanded execution JSON is persisted.

## Remaining gates and instrumentation

Actual device status, suspend/standby and combined option behavior require a
suitable isolated hardware/guest fixture. These are not inferred from error-path
checks. Other configuration/architecture profiles, whole-world aggregation,
final pkg creation, resource and performance qualification remain open.
No direct recognized SDT/DTrace, FIDL or BSM calls occur in the original source;
this conversion neither removes nor invents instrumentation. Kernel/device audit
coverage and power-management runtime remain separate review gates.
