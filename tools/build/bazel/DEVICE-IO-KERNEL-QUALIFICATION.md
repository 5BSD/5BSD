# Device I/O built-in kernel qualification

## Scope (2026-11-02)

98 selected amd64 GENERIC C objects now have native built-in declarations across
USB, HID/evdev, keyboard/mouse, sound, VT and teken. Existing source packages retain
ownership; previously unowned atkbdc and sound parent/USB directories get local
packages. 103 physical source-header contexts share identical prerequisite sets.
No production driver, audio, terminal or input source changes.

Original kernel common warning order, typed WERROR/debug/CTF and stack protection
are preserved. Every consumed option is extracted from the native config tree,
including five newly exposed keyboard/HID option outputs and empty files.
Existing schema actions provide interfaces through scoped generated-only wrappers.
Existing native USB device-ID generation remains authoritative.

## Native configurable generators

Native bsd_awk_output actions now produce the three audio headers from the original
sys/tools/sound scripts and teken_state.h from gensequences plus sequences. These
are declared inputs/actions; no Make-generated tables are imported or committed.
The shared AWK rule adds explicit operands, an optional typed string setting and
an optional -- terminator. Existing defaults preserve their exact action contracts.
The supported source-owned string settings are:

- //sys/tools/sound:feeder_eq_presets (Make FEEDER_EQ_PRESETS).
- //sys/tools/sound:feeder_rate_presets (Make FEEDER_RATE_PRESETS).

Both default to empty strings, letting the original scripts supply defaults.
Values are space-separated operands, preserving internal colons and commas;
there is no shell expansion. They pass through normal build-bsd format-5
build-settings. For example:

```json
"build-settings": {
  "//sys/tools/sound:feeder_eq_presets": "PEQ:16000,0.25,62,0.25:-6,6,1:48000",
  "//sys/tools/sound:feeder_rate_presets": "100:8:0.85 100:16:0.90"
}
```

The maintained frontend needs no new C/backend API or CLI/schema key. The manual
and this document describe the new declared source inputs. No signing, staging,
verification or package policy changes. Make remains production/default; BIP
remains excluded.

## Retained evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-device-io-make-metadata-r1-20261102 captures actual supported Make
  recipes with filemon disabled; all 98 completed reference objects retain their
  hashes. This is not a complete dynamic input or performance proof.
- bazel-kernel-device-io-amd64-ctf-r1-20261102 is the passing maintained frontend
  build with 16 workers. All 98 successful compiler actions are fresh. Immutable
  captures bind through CTF input/output digests to the compiler outputs.
- bazel-kernel-device-io-review-r1-20261102 checks 12,516 physical and 588 generated
  prerequisites, including exact default native USB/audio/teken table digests.
  Selected source hashes match the independent Make inventory. Actual warning
  order, defines, code-generation option sets, stack protection, final debug
  switch, language and forced includes match Make.

All 98 .text and .SUNW_ctf sections are byte-identical. Other allocated payloads
and layouts match except 67 exact known-source filename spellings; full string
pools and 40,037 nondebug relocations compare symbolically. Full DWARF, symbol-index
and string-table byte parity remains unclaimed. No artifacts are rewritten.
CTF graph review uses the bounded procedure in OPENZFS-KERNEL-QUALIFICATION.md:
only zero-type string addresses use verified complete canonical strings/interior
offsets; typed identities and full-literal size constraints remain strict. Separate
allocated-layout/string/relocation gates bind the same original object hashes.

bazel-device-io-awk-default-contract-{before,after}-20261102 records three existing
libmagic/ncurses AWK actions. All emitted non-ID fields, including action keys,
argv, input path sets, environment and execution configuration, remain identical.
This covers ordinary file input, awk variables and supplied stdin contexts.

bazel-kernel-device-io-audio-presets-r1-20261102 builds both overridden audio headers
through the normal frontend. Independent controls in
bazel-kernel-device-io-audio-controls-r1-20261102 execute the original Make-recorded
AWK recipes with explicit tool/script hashes and no shell. Two default controls
match the independent Make headers; two configured controls match immutable
native captures and differ from defaults. This is source-generator qualification,
not a new full Make build or an audio runtime test.

Default-restoration and unchanged-repeat native profiles retain separate receipts.
The unchanged repeat returns both exact original headers. BEP reports ten local
action-cache hits in its two-target closure and only workspace-status execution;
no generator spawn executes. The review uses BEP metrics plus immutable captures,
not invented per-spawn cache-hit events for skipped actions. Restoring defaults after changing presets
re-executes both generators: no persistent disk action cache is configured in the
current frontend. The failed variant-restoration expectation remains in
cache-review.json and is an open gate, not a cache success. Initial generator
outputs bind via actual audited compiler-input hashes to immutable object captures;
configured/restored/repeated generator outputs also have explicit top-level captures.

Compact logs stream through the upstream converter with 189 recorded bindings
verified before/after. Declaration/source/profile and review implementations remain
alongside results. Query r28 passes for 1,626 known groups and 1,801 compile actions;
reconciliation r23 finds 1,792 source matches plus two object-name and four generated-
name matches among 2,466 Make final-link products, leaving 668 unmatched. Three
auxiliary generator objects remain separate. These are known amd64 graph counts,
not complete compiled/linked coverage.

## Observability and remaining gates

The bounded source-hash-bound scan finds existing call-shaped tracing/CTR markers
in five of 98 files (HID bus, PCM channel and USB device/hub/transfer paths). Other
files do not establish missing shared hooks. Production instrumentation remains.
Real controller/device attach, hotplug/error recovery, keyboard/mouse and terminal
behavior, audio formats/rates/mixing and live tracing need runtime qualification.
The profiles use tests=[] and do not access host devices.

Add and qualify persistent action-cache support in the maintained frontend,
including variant restoration and correctness controls, before broad performance
claims. Complete native kernel link/order/identity/post-processing/install, modules,
alternate KERNCONF, ARM64/RISC-V64, full world, pkgbase/hardware publication,
bootstrap and boot/services remain open. Disk reserves pass; controlled CPU, memory,
disk I/O/use and cache/performance comparisons remain open. No host install,
upgrade or reboot occurred.
