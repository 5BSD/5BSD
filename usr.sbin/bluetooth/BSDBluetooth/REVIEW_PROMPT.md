Production-Ready BLE Feature Parity Review: blued vs BlueZ

You are reviewing the FreeBSD BLE daemon "blued" for production release.
The goal is BLE feature parity with BlueZ (Linux) for BLE through spec
version 5.2, excluding all audio paths (A2DP, AVRCP, AVDTP, BAP, LC3,
ISO channels, CIS/BIS).

CODEBASE LOCATIONS:
  Daemon source:    /usr/src/usr.sbin/bluetooth/blued/  (22 files, ~21.7k lines)
  Test suite:       /usr/src/tests/usr.sbin/bluetooth/blued/  (11 files, ~18.3k lines, 451 tests)
  Kernel L2CAP:     /usr/src/sys/netgraph/bluetooth/
  HCI control tool: /usr/src/usr.sbin/bluetooth/hccontrol/
  Spec references:  /usr/src/bluetooth-specs/Core_Specification_6_3.txt
                    /usr/src/bluetooth-specs/Core_Specification_6_3.pdf
                    /usr/src/bluetooth-specs/GATT_Specification_Supplement.pdf

LOCAL BLUEZ REFERENCE:
  BlueZ does not ship source here, but you have deep knowledge of BlueZ 5.x
  architecture.  Compare blued against BlueZ for:
  - Feature completeness (D-Bus GATT API vs blued ctl socket)
  - Security model (AppArmor vs Capsicum)
  - Testing approach (btdev/bthost emulator vs socketpair+fork)
  - Profile support (bluetoothd plugins vs monolithic daemon)
  - Kernel split (Linux l2cap.ko does ATT/SMP routing vs FreeBSD ng_l2cap
    does only segmentation)

SCOPE -- BLE features through 5.2 (non-audio):
  Core Spec Vol 3 Part F: ATT (Attribute Protocol)
  Core Spec Vol 3 Part G: GATT (Generic Attribute Profile)
  Core Spec Vol 3 Part H: SMP (Security Manager Protocol)
  Core Spec Vol 3 Part C: GAP (Generic Access Profile)
  Core Spec Vol 6 Part B: LE Link Layer
  BT 4.0: LE basics, ATT/GATT, SMP Legacy Pairing, advertising, scanning
  BT 4.1: LE dual-mode, multiple simultaneous roles, L2CAP CoC
  BT 4.2: LE Secure Connections, LE Data Length Extension, LE Privacy 1.2
  BT 5.0: 2M PHY, Coded PHY, Extended Advertising, periodic advertising
  BT 5.1: GATT Robust Caching (Database Hash), AoA/AoD direction finding
  BT 5.2: EATT (Enhanced ATT), L2CAP credit-based flow control enhancements
          (but NOT LE Audio / ISO / CIS / BIS -- those are excluded)

EXPLICITLY EXCLUDED (do not flag as missing):
  - A2DP, AVDTP, AVRCP (classic audio)
  - BAP, LC3, ISO channels, CIS/BIS (LE Audio)
  - RFCOMM, SDP (classic Bluetooth -- blued is BLE-only)
  - Mesh networking
  - Classic BR/EDR pairing (SSP, PIN)

WHAT BLUED CURRENTLY IMPLEMENTS (verify each against spec + BlueZ):
  ATT: Full client + server, MTU exchange, all request/response opcodes,
       EATT bearers (clamped to ATT_PDU_BUF_SIZE), Multiple Handle Value
       Notifications, bearer-aware routing
  GATT: All 7 discovery procedures (primary, primary-by-UUID, secondary,
        includes, characteristics, descriptors, find-by-type-value),
        Database Hash, CCCD persistence across reconnections, Service
        Changed indication on db_hash mismatch, config-driven + runtime
        service registration (ADD_SERVICE/ADD_CHAR/REMOVE_SERVICE)
  SMP: Legacy Pairing (Just Works, Passkey Entry, OOB), LE Secure
       Connections (Just Works, Numeric Comparison, Passkey Entry, OOB),
       CTKD (gated on MITM), IRK/LTK/Link Key distribution,
       RPA resolution, Keypress Notifications, SC Debug Key rejection,
       KNOB mitigation (16-byte min for SC), global rate limiting
  GAP: Central + Peripheral roles, advertising (legacy + extended),
       scanning (legacy + extended), connection establishment, privacy,
       bonding, reconnection with backoff, GATT handle caching
  HCI: LE commands via ng_hci netgraph, PHY management (1M/2M/Coded),
       Data Length Extension, Filter Accept List, Resolving List
  Profiles: HID-over-GATT (HOGP) central with Output+Feature reports,
            generic GATT peripheral with config-driven services
  Security: Bond DB encrypted at rest (AES-256-GCM, hostuuid-derived key),
            Capsicum sandbox (cap_enter + capability-limited fds),
            configurable socket pool for Capsicum reconnection
  Operations: rc.d script, SIGHUP config reload, runtime LOGLEVEL,
              BTSnoop logging, 19 control socket commands, man page

RECENT FIXES APPLIED (verify these are correct and complete):
  1. TOCTOU race in HCI event handler — conns_lock now held through
     conn->att->encrypted write; auth timeout uses needs_cleanup + self-pipe
  2. LE CoC rejection — kernel now only suppresses ConnectRsp for ATT/SMP
     fixed CIDs; LE CoC with result!=0 sends rejection to peer
  3. Execute Write perm re-check — att_check_write_perm() added in validation loop
  4. CCCD bypass via Execute Write — property validation + per-connection CCCD
     routing added in execute path
  5. ATT_PERM_READ_AUTHEN implies encryption — encryption check before auth check
  6. Bond DB synchronized — bond_db_lock mutex added, wraps all bond_db accesses
  7. Blocking ATT I/O — timeout reduced 5s→2s with documented rationale
  8. BLE name sanitization — control chars replaced with '?' in parse_ad_fields
  9. test_srv_unknown_opcode — opcode corrected from 0x7F (command) to 0x3F (request)

REVIEW STRUCTURE -- produce each section:

1. FEATURE MATRIX
   For each BLE feature in spec versions 4.0-5.2 (non-audio), create a
   table with columns: Feature | Spec Reference | BlueZ Status | blued
   Status | Gap Description. Read the actual source code to verify -- don't
   assume from headers. Mark each as: DONE (implemented), PARTIAL (partial),
   MISSING (missing). Cross-reference with Core_Specification_6_3.txt.

2. SPEC COMPLIANCE AUDIT
   For each ATT opcode handler, SMP pairing path, and GATT discovery
   procedure, verify blued handles it correctly per the Core Spec.
   Cross-reference with Core_Specification_6_3.txt. Flag any deviations.
   Check error handling: does blued return the correct ATT/SMP error codes
   for each failure case?

3. SECURITY REVIEW
   - SMP: Are all pairing methods correctly implemented? Check the IO
     capability mapping tables (Vol 3 Part H Table 2.8). Verify key
     generation, confirm value computation, DHKey check.
   - Bond DB: Is the encryption implementation correct? Key derivation?
   - Key storage: Are keys zeroed after use? Is the bond DB encrypted?
   - Privacy: Is RPA rotation implemented? RPA timeout configurable?
   - ATT permissions: Are read/write/encrypt/auth permissions enforced
     independently (no bypass when multiple permission bits set)?
   - Input validation: For every recv() of a PDU from a peer, verify
     length checks before accessing fields.
   - Capsicum: Is the sandbox correctly applied? Are all fds limited?
   - Rate limiting: Is the global rate limiter effective?
   - Verify all 9 recent fixes are correct and complete.

4. BLUEZ COMPARISON
   Compare blued's architecture and feature set against BlueZ 5.x:
   - D-Bus GATT API vs ctl socket — feature gap?
   - Plugin/profile model vs monolithic daemon — tradeoffs?
   - btdev/bthost testing vs socketpair+fork — what can't be tested?
   - Kernel-userspace split — Linux does more in kernel, FreeBSD less.
     What are the security and performance implications?
   - MGMT interface vs blued ctl commands — missing management features?
   - Service registration: BlueZ RegisterApplication vs blued ADD_SERVICE

5. TEST COVERAGE ANALYSIS
   Current test suite: 451 tests across 11 files.
   For each function in att.c, att_server.c, smp.c, conn.c, ctl.c,
   config.c, hci_util.c, gatt.c: is it tested? List untested public
   functions and untested error paths. Compare against BlueZ test coverage.

   Known gaps to investigate and fill:
   - blued.c main event loop: zero test coverage
   - Reconnection logic: exponential backoff untested
   - HOGP: minimal coverage (4 notification tests)
   - hci_log.c: only stubs
   - Negative crypto inputs: all crypto tests use valid inputs
   - config_test:test_config_duplicate_keys: pre-existing failure — FIX THIS

6. OPERATIONAL READINESS
   - Daemon lifecycle: startup, shutdown, SIGHUP reload, PID file, rc.d
   - Logging: BTSnoop capture, structured logging levels, syslog, runtime
     LOGLEVEL command
   - Configuration: all config keys documented? Validated? Reloadable?
   - Control socket: all 19 commands implemented and tested?
   - Capsicum sandbox: correctly applied? Configurable socket pool?
   - Resource limits: max connections, max bonds, max CCCDs, fd exhaustion
   - Bond DB encryption: key derivation correct? Backward compatible?
   - HOGP: Input, Output, and Feature reports all working?
   - GATT handle caching: does it correctly skip rediscovery?

7. KERNEL INTEGRATION
   Review the ng_l2cap_ulpi.c and ng_btsocket_l2cap.c changes.
   Are they correct? Do they break any existing L2CAP users?
   Is the fixed-channel routing (ATT CID 0x0004, SMP CID 0x0006)
   spec-compliant? Is incoming LE CoC correctly wired?

8. PRIORITIZED PUNCH LIST
   Consolidate all findings into: Critical (blocks release), High
   (should fix), Medium (before v1.1), Low (future). For each item,
   name the specific file, function, line number, and what needs to change.

OUTPUT FORMAT:
   Use tables where possible. Be specific -- cite spec sections, function
   names, line numbers. Don't list things that are already implemented
   correctly. Focus on gaps, risks, and deviations. Target ~3000 words.
