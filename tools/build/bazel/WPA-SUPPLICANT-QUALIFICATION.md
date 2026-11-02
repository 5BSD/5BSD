# Native wpa_supplicant — 2026-11-02

## Source and configuration ownership

The native cc_binary declares the original 23 baseline translation units,
OpenSSL's pasn_supplicant.c and the three EAPOL-controlled sources. Fresh Make
references select 27/24 sources with OpenSSL and EAPOL enabled/disabled, and
26/23 with the internal backend. The physical provider owns the 106 observed
WPA headers from all four reference descriptions, preserving actual include
contexts. No production Make interpretation, copied library, omitted source,
absolute diagnostic replacement or host-resource fallback is introduced.

The native graph preserves Make's thirteen private archive dependencies and
actual order, preceded by conditional ssl/crypto and original pcap/util DSOs.
Compiler policy retains ordinary program PIE flags, CONFIG_BACKEND_FILE, the
local eleven-macro EAPOL group and the real second Makefile.inc group. Program
source and behavior are unchanged.

Source-owned installation retains package=wpa, /usr/sbin/wpa_supplicant, its
debug companion, both original manuals and the optional original configuration
example at /usr/share/examples/etc/wpa_supplicant.conf. The existing examples
setting controls that payload and its source package directory record.

## Performed qualification

All evidence paths are under /usr/obj/usr/src. Builds use the validated November
2 SDK, normal build-bsd format-5 inputs, sixteen jobs and the unchanged 18 GiB
start / 16 GiB stop guard, which never fired. Explicit execution-log-format=
compact uses the maintained frontend API; complete execution logs are retained.

- Two fresh independent OpenSSL Make builds pass, selecting all thirteen
  explicitly hash-bound private archives in DPADD, LDADD and the actual link
  recipe. Both corresponding native program/install/test configurations pass.
- Immutable ELF comparisons retain exact ordered NEEDED entries (ssl, crypto,
  pcap, util, libc), program/interpreter/version/import contracts, PIE, RELRO/NOW
  and absence of text relocations, executable stack, writable/executable loads
  and embedded search paths. Full linked/debug byte identity and complete ABI
  equivalence remain unqualified.
- All 51 program objects match raw text, 104 raw constant sections and ordered
  macro/warning vectors. All 5,380 physical prerequisite hashes (221 unique)
  match actual native action inputs. The exact 27/24 program object orders and
  26 private archive selections match the recorded Make links. All 28,069 raw
  nondebug relocations match, including numeric symbol indices and addends.
- Both native install captures match eight Make records each: type, owner/group,
  mode, package/debug tags, tar metadata, both decompressed manual payloads and
  the original example bytes. Four installed native/Make debug-link CRCs pass.
  This does not establish final pkg archive/dependency composition.
- Retained hashed test logs report eight real unittest methods across two Bazel
  wrapper cases. Non-root tests exercise help, the original two-line version
  response, illegal-option handling and declared DSO loader closure. Those
  command-line branches return before wpa_supplicant_init/driver setup. The BSD
  build's fd workaround is inactive; os_program_init only seeds the process RNG.
  No host interface, network, service, account, clock or tracing is modified.

The compact logs are 144,659 and 526,050 bytes. Audits use Bazel's original
upstream converter streaming JSON directly into execution_log.stream_objects;
no expanded log is written and no custom protobuf decoder is used. Every one
of its 189 recorded inputs is hash-checked before and after conversion, and
zero converter exit status is required. This storage observation is not a
controlled build-speed, memory or system performance comparison.

Primary evidence: bazel-wpa-supplicant-reference-matrix-20261102.json;
bazel-wpa-supplicant-source-description-20261102.json;
bazel-wpa-supplicant-native-matrix-r3-20261102.json;
the two bazel-wpa-supplicant-*-object-audit-r4-20261102/report.json files and
their converter-provenance.json files; bazel-wpa-supplicant-elf-audit-20261102;
the corresponding install/relocation reports; and
bazel-wpa-supplicant-test-log-audit-20261102.json.

## Retained failures and provenance

The initial native analysis correctly rejected a duplicate driver_bsd.c export;
only the redundant export was removed, retaining the existing source label.
The second build compiled/linked but rejected an incorrect authored test that
expected one version line. The maintained source explicitly includes copyright
as its second line; the new test now asserts both lines. Original failure logs
and reports remain. No production source or imported test was weakened.

The successful default retry reused those compiled objects. Its immutable
program and every object/parameter snapshot must match the preserved failed-test
build outputs, then match that build's actual compact execution digests and the
fresh Make recipes/prerequisites. The failed test result is not qualification;
current successful program/install/test receipts are independently required.

The after-build snapshot wrapper detected three stale EAPOL objects in the
shared output tree after the no-EAPOL build. Both frontend guard/receipt records
already report success; the wrapper's assertion failure is retained separately.
Only the explicitly selected 24 source objects are provisionally captured, then
proved against all 24 actual compiler outputs and the exact actual link order.
The stale files are reported and retained, not deleted or counted as current
outputs. An audit-only copied target label was also rejected before comparison;
its corrected audit is separate. Mutable bazel-bin is never the artifact oracle.

## Remaining gates

Both independent internal-backend Make consumers fail on missing crypto APIs;
those actual failures and command/log hashes remain in
bazel-wpa-supplicant-internal-failures-20261102.json. No SAE/EHT/EAP feature is
silently disabled to pass. Source lists/private archives are not internal
consumer qualification. Arbitrary WPA_SUPPLICANT_CFLAGS/LDADD and optional
EAP-AKA/SIM/GPSK/PAX/SAKE/PCSC custom builds need explicit native modeling and
independent references; current qualification covers the maintained defaults.
Examples-disabled and other packaging/configuration profiles remain separate.

All sixteen private directories and all five WPA programs now have bounded
native qualification. Family aggregation must preserve wpa and hostapd package
contexts for shared directories. Complete family pkg construction, cross-userland,
control sockets, root driver startup, wireless association/authentication/EAP,
audit-event delivery, full world/system/boot and controlled performance remain
open. The call-shaped source scan finds no recognized direct SDT/DTrace/audit/
FIDL calls in these 27 sources; shared instrumentation needs runtime review.

Existing format-5 targets, typed WPA selections and the maintained compact-log
API cover build-bsd. No new frontend C, staging, signing, verification,
publication or manual interface is needed. Make remains production/default.
