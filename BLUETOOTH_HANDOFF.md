# Bluetooth production-readiness handoff

## Completed and verified

- Per-adapter public capability API: `ADAPTER_CAPS` and `ble_adapter_caps()`.
- Periodic advertising/synchronization public slice: daemon, `libble`,
  `bluedctl`, manpage, events, DTrace/probe-tap, HCI emulator, and unit tests.
- Complete PAST public slice: sync and advertising-set transfers, receive
  enable, per-peer/default receive policy, and periodic advertiser-list
  management, separately capability-gated by sender/recipient/periodic roles.
- ISO remains explicitly transport primitives only; no LE Audio profiles.
- Mesh `models` inventory is public through `meshd`/`meshctl`; it exposes no
  key material and includes commissioned binding/subscription/publication counts.
- HCI emulator now handles periodic advertising, PAST receive-enable, and
  PAST transfer command encodings.
- Hardware-gated periodic advertising smoke test added to `hci_hw_test`.
- SMP pairing coverage is enabled for SC OOB, legacy EncKey distribution, and
  SignKey distribution; the peer mocks complete without timeout-driven stalls.
- PB-GATT provisioning is integrated through `meshd`/`meshctl`: automatic
  0x1827/0x2ADB/0x2ADC discovery, Data Out subscription, MTU-aware Data In
  writes, Proxy-PDU SAR, disconnect/error rollback, and peer-driven DevKey
  agreement coverage.
- EATT has explicit daemon-owned open/close lifecycle APIs and operator verbs;
  ECBFC has an owned multi-channel `libble` session with borrowed-vs-transferred
  FD semantics, per-channel OMTU, reconfiguration, and deterministic cleanup.
- Extended advertising supports multiple nonzero, client-owned set handles
  with configure/data/enable/remove lifecycle, disconnect cleanup, `libble`
  ownership wrappers, operator verbs, and lifecycle tests; handle zero is the
  default advertising set.
- Generic Power OnOff is a complete Mesh vertical slice: Server and Setup
  Server access handlers, Off/Default/Restore state binding to Generic OnOff,
  Composition Page 0 and Configuration Database registration, client send
  command, and focused model/daemon tests.
- Generic Power Level is a complete Mesh vertical slice: Actual/Last/Default/
  Range state, TID and range validation, OnOff/Level/OnPowerUp bindings, Server
  and Setup Server access handlers, client builders/status caches, composition
  and commissioning inventory, current-schema persistence, and power-level/default/
  range operator commands.
- Generic Battery is a complete read-only Mesh vertical slice: strict eight-
  octet status codec, prohibited flag/value checks, Server and Client access
  models, composition/commissioning inventory, local telemetry injection, and
  focused model/daemon tests.
- Generic Location is a complete Mesh vertical slice: Global and Local codecs,
  Server/Setup/Client access procedures, signed operator parsing, composition
  and commissioning inventory, current-schema persistence, and restart/model tests.
- Generic Default Transition Time is registered and commissionable with
  validated Get/Set/Set-Unacknowledged/Status handling, client builders,
  Composition/Configuration Database inventory, and the `transition` operator
  command.  The reserved unknown step-count encoding is rejected.
- Sensor is a complete Mesh vertical slice: Descriptor, Sensor, Column,
  Series, Cadence, Settings, and Setting procedures; MPID Format A/Format B
  codecs; property-width and percentage cadence encodings; setup access
  enforcement; ordered bounded property/column registries; application-defined
  column comparison; Server/Setup/Client models; composition and commissioning
  inventory; operator configuration; transactional client status decoding;
  current-schema persistence; and focused wire, model, daemon, and restart
  tests.
- Time, Scene, and Scheduler are complete Mesh vertical slices: Time/Role/
  Zone/TAI-UTC Delta procedures and delayed changes; Scene store/recall/delete
  snapshots of bound Generic state; Scheduler's validated packed action
  register; Server/Setup/Client procedures; composition and commissioning
  inventory; operator commands; current-schema persistence; and focused model,
  daemon, and restart tests.
- Lighting is locally integrated as complete application-model slices for
  Light Lightness, CTL, HSL, xyL, and LC: SIG model registration, composition
  and configuration-database inventory, Generic state bindings, operators,
  persistence, protocol tests, and LC property edge coverage are present.
  Light LC Mode, Occupancy Mode, and Light OnOff message formats are audited
  against Mesh Model 1.1, including optional transition fields and status
  forms.  A full model-by-model requirements matrix remains useful.
- The meshd node store persists application-model state
  (OnOff, Level, Default Transition Time, and Power OnOff) while retaining
  with one exact current schema.  Because this code has not shipped and the
  format is not Bluetooth-standardized, non-current versions are rejected
  instead of carrying invented compatibility branches.  Restart round-trip
  coverage is enabled.

## Completed slice: LE path-loss reporting

Implemented:

- Daemon command:
  `PATH_LOSS <addr> <low> <low-hyst> <high> <high-hyst> <min-time> <on|off>`.
- The command resolves a live connection, rejects controllers without
  `LE_FEAT_PATH_LOSS_MONITORING` before HCI I/O, validates all fields, applies
  parameters, then enables/disables reporting.
- `libble`: `ble_path_loss_reporting()` and public controller feature bits.
- `bluedctl path-loss` and its manpage documentation.
- `EVENT PATH_LOSS handle=... loss=... zone=...` for monitor clients.
- DTrace/probe-tap path-loss event probe.

Completed for promotion:

1. `ctl_test` covers unsupported controllers, invalid thresholds, command
   parameter mapping, and an injected HCI-parameter failure (which must not
   proceed to enable reporting).
2. `libble_test` covers command serialization and invalid/null inputs.
3. `API_GAP_ANALYSIS.md` explicitly scopes the public API to path-loss
   reporting; TX-power reporting remains internal pending its own event/API
   slice.

## Remaining local software gates, in recommended order

1. Continue the normative Bluetooth specification audit against the local
   `/usr/src/bluetooth-specs` corpus and official Mesh specifications: maintain
   a requirements-to-code-and-test matrix and record the exact revision and
   section for each decision.
2. Complete a production code-quality pass: BSD/Clang formatting, public API
   and ownership review, error-path and bounds audit, static analysis, and
   `git diff --check`; reject compressed or inconsistent source before merge.
3. Complete a test-quality pass: enumerate each new public procedure and
   state transition, add positive/negative/idempotency/persistence coverage,
   run the focused ATF suite under Kyua where the test layout supports it, and
   publish the exact count of net-new cases and results.
4. Implement virtio-bluetooth from the normative virtio device specification,
   including feature negotiation, queue lifecycle/reset, memory ordering,
   transport error recovery, kernel integration, and emulator-backed tests.
5. Modernize virtio PCI discovery and identification using the modern virtio
   PCI capability layout and device IDs, while retaining legacy transport only
   where the virtio specification requires it; add probes for transitional and
   modern-only devices and regression coverage for capability parsing.

## External gates that cannot be synthesized locally

- Bluetooth SIG Profile Tuning Suite execution, qualification, and declaration.
- Hardware matrix results: legacy-only LE, BT 5.0 extended advertising, and
  BT 5.2 ISO-capable controllers.
- A pinned local NimBLE checkout for parity comparison.
- Direction-finding antenna-array validation.
- Hardware-backed virtio-bluetooth interoperability across at least one
  modern-only and one transitional PCI device after the local emulator suite.

## Validation architecture

- SIG-derived unit tests hand-encode Core 6.3, GATT, and Mesh 1.1 vectors and
  message layouts.  They are regression tests, not official SIG test cases.
- The HCI emulator validates controller command/event framing, feature gates,
  faults, timers, encryption, ISO primitives, and simultaneous ACL links.
- `btpeer` independently emits and consumes ATT/SMP traffic over the emulator;
  scenario, dataflow, and equivalence tests exercise the real host stack.
- Hardware-only ATF cases skip when no suitable controller or privilege is
  available.  Their skips are environmental and are reported separately from
  local protocol coverage.

## Last successful verification commands

```sh
make -C usr.sbin/bluetooth/blued -j2
make -C usr.sbin/bluetooth/bluedctl -j2
make -C lib/libble -j2
make -C tests/usr.sbin/bluetooth/blued -j2
make -C tests/usr.sbin/bluetooth/blued ctl_test -j2
make -C tests/usr.sbin/bluetooth/blued hci_emulator_test -j2
make -C tests/usr.sbin/bluetooth/blued meshd_test -j2
git -C /usr/src diff --check
```

Focused tests that passed include periodic/PAST control tests, the periodic
and PAST emulator test, `libble_test test_periodic_and_past_commands`, and
`meshd_test ctl_exec`.

## Resume note from 2026-07-13

When building from this sandbox, use an object directory outside the source
tree, for example:

```sh
env MAKEOBJDIRPREFIX=/tmp/codex-obj make -C lib/libmesh -j2
env MAKEOBJDIRPREFIX=/tmp/codex-obj make -C usr.sbin/bluetooth/meshd -j2
```

Running dependent mesh builds in parallel can race `meshd` against a stale
`libblemesh`; build `lib/libmesh` first, then `usr.sbin/bluetooth/meshd`.
Verified in that order: `lib/libmesh`, `usr.sbin/bluetooth/meshd`,
`usr.sbin/bluetooth/meshctl`, `lib/libble`, `usr.sbin/bluetooth/blued`,
`usr.sbin/bluetooth/bluedctl`, `tests/usr.sbin/bluetooth/blued`, and
`git diff --check`.
