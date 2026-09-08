# Bluetooth standard conformance: state of traceability

Status: assessment, 2026-09-08. Applies to `usr.sbin/bluetooth/blued`,
`usr.sbin/bluetooth/meshd`, `lib/libble`, `lib/libmesh` and the test suite in
`tests/usr.sbin/bluetooth/blued`.

This document says what is and is not actually traced to a published Bluetooth
specification, with machine-checked numbers rather than assertions. Every count
below is reproducible by running
`tests/usr.sbin/bluetooth/blued/spec_conf_generate.sh`.

---

## 1. Headline

| Question | Answer |
| --- | --- |
| Requirement rows in `spec_requirements.tsv` (317 lines, 1 header) | 316 |
| ...that cite a published specification only | 230 (72.8%) |
| ...that cite a published specification *and* our own source | 37 (11.7%) |
| ...that cite **only** our own source tree | 49 (15.5%) |
| ...that cite a document **not present in this tree** | 69 (21.8%) |
| ...that are normative **and** externally oracled **and** backed by an in-tree document | **123 (38.9%)** |
| Normative sentences extracted from Core 6.3 for the layers we implement | 2255 |
| ...classified NOT-APPLICABLE (controller/link-layer/BR-EDR-only) | 185 |
| ...with section-level coverage by an externally-oracled test | **842 (40.7% of applicable)** |
| ...UNCOVERED | 1228 |

The two bolded numbers are the honest ones. Everything else in the existing
`make spec-traceability` output — "317/317 implemented requirements covered" —
is a tautology: the audit only checks that each row it was given has *some*
matching Kyua case, so a row can be added, matched, and counted without any
normative content at all.

Even the 842 is an **upper bound**. The existing matrix cites specification
*sections*, never individual normative sentences, so the strongest claim its
data supports is "a test exists that exercises this section and has an oracle
independent of our code". It is not evidence that the particular `shall` is
asserted anywhere. Read it as "plausibly covered", not "conformance-tested".

---

## 2. Audit of the existing matrix (task 1)

Classification of `exact_reference` across all 316 requirement rows:

| Class | Count | Meaning |
| --- | --- | --- |
| `normative` | 230 | cites a published specification only |
| `mixed` | 37 | cites a specification *and* our own `.c`/`.h` files |
| `implementation` | 49 | cites only our own source tree, or the FreeBSD kernel |

The 49 implementation rows are contracts about our code wearing conformance
clothing. They are (ids as they appear in the file):

`IMPL-SMP-CONNECTION-LIFECYCLE`, `IMPL-SMP-PAIRING-POLICY`,
`IMPL-SMP-TRANSPORT-ADAPTER`, `IMPL-SMP-CRYPTO-HELPERS`, `IMPL-BOND-DB`,
`IMPL-BOND-PC4`, `IMPL-BOND-ATOMIC-FAILURE`, `IMPL-SMP-FAIL-CLOSED`,
`IMPL-MESH-TRANSPORT`, `IMPL-MESH-FRIEND`, `IMPL-MESH-PROXY`, `IMPL-MESH-DF`,
`IMPL-MESH-IV`, `IMPL-MESH-RELAY`, `IMPL-MESH-NETWORK`, `IMPL-MESH-MANAGER`,
`IMPL-MESH-CFG11`, `IMPL-MESH-CFG-MODEL`, `IMPL-MESH-PROVISION`,
`IMPL-MESH-REMOTE`, `IMPL-HCI-HARDWARE`, `IMPL-HCI-KERNEL-EVENTS`,
`IMPL-HCI-PERIODIC-DF`, `IMPL-HCI-ISO-API`, `IMPL-HCI-POWER-API`,
`IMPL-HCI-ERROR-ARMS`, `IMPL-HCI-ENCODER-DRIVE`, `IMPL-HCI-OFFLINE`,
`IMPL-HCI-EMU-DEEP`, `IMPL-SCAN-PARSER`, `IMPL-ISO-LIFECYCLE`,
`IMPL-ISO-SOCKET`, `IMPL-L2CAP-DATA`, `IMPL-L2CAP-DATA-DEEP`,
`IMPL-ATT-FAULT`, `IMPL-ATT-CLIENT`, `IMPL-ATT-CLIENT-API`,
`IMPL-ATT-SERVER-EDGE`, `IMPL-ATT-SERVER-DISPATCH`,
`IMPL-ATT-SERVER-NEGATIVE`, `IMPL-ATT-MULTIPLE-HANDLE-NOTIFY`,
`IMPL-ATT-NOTIFY-INDICATE`, `IMPL-ATTDB-CCCD`, `IMPL-ATTDB-CAPACITY`,
`IMPL-GATT-SCENARIO`, `IMPL-GATT-UNIT`, `IMPL-PERIPHERAL-INTEGRATION`,
`IMPL-GAP-AD-DISPLAY`, `IMPL-EMU-PEER-EQUIVALENCE`.

(`IMPL-SMP-SECRET` classifies as `mixed`: it cites IEEE Std 1003.1-2024 for the
file-permission behaviour alongside `smp_keys.c`. The POSIX citation is real but
is not a Bluetooth conformance requirement.)

Most of these *do* have a real requirement underneath them; the citation is
simply pointed at the wrong document. The correct citations are:

| Row | Underlying normative requirement |
| --- | --- |
| `IMPL-ATT-SERVER-DISPATCH`, `IMPL-ATT-SERVER-NEGATIVE` | Core 6.3 Vol 3 Part F §3.4.1.1 (Error Response), §3.4.8 (opcode summary), §3.4.9 (response summary) — which request maps to which error is fully normative |
| `IMPL-ATT-NOTIFY-INDICATE`, `IMPL-ATT-MULTIPLE-HANDLE-NOTIFY` | Vol 3 Part F §§3.4.7.1–3.4.7.4 |
| `IMPL-ATT-CLIENT`, `IMPL-ATT-CLIENT-API` | Vol 3 Part F §§3.4.2–3.4.6; EATT bearer rules §3.2.11 |
| `IMPL-ATTDB-CCCD` | Vol 3 Part G §3.3.3.3 (Client Characteristic Configuration descriptor); per-client state is normative, not a local choice |
| `IMPL-GATT-SCENARIO`, `IMPL-GATT-UNIT`, `IMPL-PERIPHERAL-INTEGRATION` | Vol 3 Part G §§2–4, §7.3 (Database Hash), Appendix B |
| `IMPL-SMP-PAIRING-POLICY`, `IMPL-SMP-FAIL-CLOSED` | Vol 3 Part H §§2.3.5, 2.4.6, 3.5.1–3.5.7 |
| `IMPL-BOND-DB`, `IMPL-SMP-SECRET`, `IMPL-BOND-ATOMIC-FAILURE`, `IMPL-BOND-PC4` | genuinely local storage contracts — **no** underlying spec requirement; keep them, just stop counting them |
| `IMPL-SMP-CRYPTO-HELPERS` | Vol 3 Part H §2.2 byte-order conventions (the swap is normative; the helper signature is not) |
| `IMPL-SCAN-PARSER`, `IMPL-GAP-AD-DISPLAY` | Core Specification Supplement v15 Vol 1 Part A §1 (AD types and format) — document now in tree as `CSS_v15.pdf`/`.txt`; the six rows still citing "CSS v12" need a version sweep |
| `IMPL-HCI-*` | Vol 4 Part E §§7.7/7.8 for the specific commands; the wrapper signatures are local |
| `IMPL-ISO-*`, `IMPL-L2CAP-DATA*`, `IMPL-HCI-KERNEL-EVENTS` | FreeBSD kernel contracts; genuinely implementation, keep as such |
| `IMPL-MESH-*` | Mesh Protocol 1.1.1 / Mesh Model 1.1.1 — documents now in tree as `MshPRT_v1.1.1.pdf`/`.txt` and `MshMDL_v1.1.1.pdf`/`.txt`; citations are verifiable and 3,796 mesh requirements are now classified (§6) |
| `IMPL-EMU-PEER-EQUIVALENCE`, `IMPL-HCI-EMU-DEEP` | test-harness contracts; genuinely implementation |

### Oracle column

| Oracle class | Count | Basis |
| --- | --- | --- |
| `external` | 175 | claims a spec-extracted constant, published vector, NIST/FIPS/RFC KAT, or independently constructed byte sequence |
| `mixed` | 40 | external for the wire values, local policy for the rest — self-declared in the row text |
| `internal` | 101 | compares our code to our code, or asserts a local API contract |

Note that "external" here is a *claim* parsed out of the prose in the oracle
column. Only a subset is machine-verifiable: the constants in
`spec_core63_generated.h` and `spec_assigned_generated.h` are mechanically
re-derived from the SIG documents by `check_generated_oracles.sh`, and those
are genuinely external. The rest are external by author assertion.

---

## 3. Requirement extraction (task 2)

`spec_conf_generate.sh` produces `spec_conf_requirements_generated.tsv`:
2255 normative sentences, deterministic and regenerable.

| Volume / Part | Layer | Extracted |
| --- | --- | --- |
| Vol 3, Part A | L2CAP (incl. LE credit-based, ECBFC, EATT) | 564 |
| Vol 3, Part C | GAP | 345 |
| Vol 3, Part F | ATT | 273 |
| Vol 3, Part G | GATT | 254 |
| Vol 3, Part H | SMP | 174 |
| Vol 4, Part E | HCI, scoped to commands blued issues | 560 |
| Vol 6, Part B | Link Layer, host-responsible sections only | 85 |

Keyword breakdown: 2011 `shall`, 201 `shall not`, 41 `must`, 2 `must not`.

HCI is scoped by `spec_conf_hci_scope.awk`, which greps
`usr.sbin/bluetooth/blued` for `NG_HCI_OCF_*` symbols and maps each to its Core
6.3 section heading by expanded word-token containment. All 97 opcodes blued
references map to a section; 8 need an explicit override (documented inline)
because the FreeBSD `ng_hci` vocabulary differs from Core 6.3 — `WHITE_LIST`
versus "Filter Accept List", `START_ENCRYPTION` versus "LE Enable Encryption",
`PERIODIC_ADV_LIST` versus "Periodic Advertiser List". The result is 103
sections, plus the LE Meta event chapter and the six core events blued consumes.

Vol 6 Part B is restricted to §1.3 (device addresses), §4.7, and §6 (privacy,
RPA generation and resolution) — the parts where the host, not the controller,
carries the obligation.

The generator is drift-checkable: `spec_conf_generate.sh --check` fails if the
checked-in catalogue, its coverage classification, or the ranked gap list no
longer matches what the specification text produces.

---

## 4. Coverage (task 3)

| Volume / Part | Applicable | Covered | % |
| --- | --- | --- | --- |
| Vol 3, Part F (ATT) | 273 | 227 | 83.2% |
| Vol 3, Part H (SMP) | 174 | 103 | 59.2% |
| Vol 4, Part E (HCI) | 466 | 264 | 56.7% |
| Vol 3, Part G (GATT) | 253 | 101 | 39.9% |
| Vol 6, Part B (LL/privacy) | 58 | 16 | 27.6% |
| Vol 3, Part A (L2CAP) | 522 | 120 | 23.0% |
| Vol 3, Part C (GAP) | 324 | 11 | **3.4%** |
| **Total** | **2070** | **842** | **40.7%** |

Classification rules, stated so the numbers can be argued with:

* **COVERED** — a row in the matrix cites this requirement's *exact* section
  and that row's oracle claims an origin outside the implementation.
* **UNCOVERED / `ancestor-section-only-no-direct-citation`** (350) — the matrix
  cites an ancestor section (`§3.4` standing for all of `§3.4.x`). Inheritance
  is not evidence; these are not counted as covered.
* **UNCOVERED / `section-touched-weak-oracle`** (67) — the section is cited, but
  only by rows whose oracle compares our code to our code.
* **UNCOVERED / `no-matrix-row-cites-section`** (811) — nothing in the matrix
  mentions this section at all.
* **NOT-APPLICABLE** (185), with the deliberate-omission evidence:
  * `controller-responsibility` (99) — the sentence's subject is "the
    Controller". blued is a host.
  * `link-layer-responsibility` (23) / `physical-layer-responsibility` (1) —
    likewise.
  * `br-edr-l2cap-mode-not-applicable-to-le` (41) — Enhanced Retransmission,
    Streaming, Flow Control modes and FCS. LE bearers support only Basic, LE
    Credit Based Flow Control, and Enhanced Credit Based Flow Control.
  * `br-edr-service-access-not-implemented` (21) — GAP security modes 2/3/4.
    blued exposes no BR/EDR service-access layer: no SDP, no RFCOMM, no classic
    L2CAP server. Its only BR/EDR surface is cross-transport key derivation
    (`smp.h` `SMP_KEY_DIST_LINK_KEY`), which lives in Vol 3 Part H and is *not*
    excluded.

**GAP (Vol 3 Part C) at 3.4% is the single worst result in this document.**
GAP is where discoverability/connectability modes, LE security modes, address
policy, and the privacy state machine live — exactly the areas a peer device
exercises first. There are 11 covered requirements out of 324 applicable.

---

## 5. Ranked gap list (task 4)

Ranking weights (`spec_conf_rank.awk`) encode the defect classes this project
has actually shipped, from the ~200 bugs the parity effort found: wire
representation and byte order, key-distribution rules, state-machine and
PDU-legality transitions, error-code selection, and per-connection versus
shared state — plus security relevance and mandatory-for-interoperability
language, and a per-layer weight.

Distribution across the 1228 uncovered requirements: security 201,
state-machine 175, wire-representation 147, per-connection-state 128,
prohibition 122, key-distribution 105, error-code-selection 77.

The full ordered list is `spec_conf_gaps_ranked.tsv`. The top 40 distinct work
items:

| # | Requirement | Layer §| Risk | Test that should exist |
| --- | --- | --- | --- | --- |
| 1 | `CORE63-V3PG-4.8.1-01` | GATT §4.8.1 | ATT_READ_REQ must yield Insufficient Authentication / Authorization / Encryption Key Size — the exact error, not any error | ATT server read on an unencrypted link with each permission class, asserting the exact error octet |
| 2 | `CORE63-V3PG-4.8.3-04` | GATT §4.8.3 | same for ATT_READ_BLOB_REQ | as above, long-read path |
| 3 | `CORE63-V3PG-4.8.4-01` | GATT §4.8.4 | same for ATT_READ_MULTIPLE_REQ | error selection when *any* handle in the set fails |
| 4 | `CORE63-V3PG-4.8.5-01` | GATT §4.8.5 | same for ATT_READ_MULTIPLE_VARIABLE_REQ | as above, variable-length form |
| 5 | `CORE63-V3PG-4.9.3-04` | GATT §4.9.3 | same for ATT_WRITE_REQ | write permission matrix |
| 6 | `CORE63-V3PG-4.12.1-01` … `-4.12.4-04` | GATT §§4.12.1–4.12.4 | same for characteristic-descriptor read/write/prepare/execute | descriptor permission matrix, all four PDUs |
| 7 | `CORE63-V3PC-10.3.1-07` | GAP §10.3.1 | too-short encryption key must be rejected with Encryption Key Size Too Short | key-size enforcement across the ATT/GATT boundary |
| 8 | `CORE63-V3PH-2.4.2.3-02` | SMP §2.4.2.3 | generated LTK shall not be longer than negotiated key size | LTK truncation KAT at every negotiated size 7..16 |
| 9 | `CORE63-V3PH-2.4.4.2-03` | SMP §2.4.4.2 | same for the Secure Connections path | as above, SC |
| 10 | `CORE63-V3PC-10.3.2-11` | GAP §10.3.2 | shall not request pairing when relying on error codes | pairing-initiation state machine negative case |
| 11 | `CORE63-V3PA-10.2-12` | L2CAP §10.2 | connection must fail when key size is too short | LE credit-based channel rejection |
| 12 | `CORE63-V3PC-5.2.2.2-06` | GAP §5.2.2.2 | `L2CAP_CREDIT_BASED_CONNECTION_RSP` result 0x0005/0x0006 selection | exact result-code oracle per failure cause |
| 13 | `CORE63-V3PH-3.5.2-01` | SMP §3.5.2 | Pairing Request over BR/EDR without CTKD support must fail | CTKD negative path |
| 14 | `CORE63-V6PB-6.2.1-04` | LL §6.2.1 | InitA identity-address handling when peer is in the Resolving List with a non-zero IRK | RPA/identity-address selection oracle |
| 15 | `CORE63-V6PB-6.2.2-02` | LL §6.2.2 | TargetA shall be an RPA when an IRK is available | directed-advertising address-type matrix |
| 16 | `CORE63-V6PB-6.2.3-03` | LL §6.2.3 | ScanA identity-address handling | scan-request address resolution |
| 17 | `CORE63-V6PB-6.2.5-01` | LL §6.2.5 | TargetA RPA rule, extended form | extended-advertising variant of #15 |
| 18 | `CORE63-V6PB-6.4-06` | LL §6.4 | AdvA identity-address handling on the initiator side | initiator-side resolution |
| 19 | `CORE63-V3PC-12.6-01` | GAP §12.6 | Encrypted Data Key characteristic shall not be writable | GATT permission assertion on the built-in service |
| 20 | `CORE63-V3PC-12.5-01` | GAP §12.5 | Resolvable Private Address Only characteristic is exactly 1 octet | wire-length oracle |
| 21 | `CORE63-V3PC-14.1-05` | GAP §14.1 | shall not derive a BR/EDR link key from a weaker LE LTK | CTKD strength-comparison matrix |
| 22 | `CORE63-V3PC-9.4.2.2-01` | GAP §9.4.2.2 | Bonding_Flags = No Bonding, and bonding information shall not be exchanged | pairing-request field oracle in non-bonding mode |
| 23 | `CORE63-V3PF-4-04` | ATT §4 | Insufficient Authorization/Authentication shall not be used for ATT_FIND_INFORMATION_REQ | prohibited-error-code assertion |
| 24 | `CORE63-V3PG-8.1-03` | GATT §8.1 | same prohibition, GATT wording | as above |
| 25 | `CORE63-V3PH-1-01` | SMP §1 | invalid peer public key shall fail pairing with Pairing Failed | SC public-key validation negative vectors |
| 26 | `CORE63-V3PH-2.4.6-01` | SMP §2.4.6 | Peripheral shall not send Security Request while pairing or encryption is in progress | pairing state-machine legality matrix |
| 27 | `CORE63-V3PA-7.11-04` | L2CAP §7.11 | MTU/MPS take effect after `L2CAP_CREDIT_BASED_RECONFIGURE_RSP` is sent | ECBFC reconfigure ordering |
| 28 | `CORE63-V3PA-3-03` | L2CAP §3 | Information Payload shall not exceed the peer's MPS | outbound fragmentation bound |
| 29 | `CORE63-V3PG-4.3.1-02` | GATT §4.3.1 | MTU exchange shall not be used on a BR/EDR physical link | bearer-legality assertion |
| 30 | `CORE63-V3PG-5.1.2-06` | GATT §5.1.2 | Key_Type must be Unauthenticated or Authenticated Combination Key | key-type validation |
| 31 | `CORE63-V4PE-7.8.104-07` | HCI §7.8.104 | all 16 Broadcast_Code octets shall be zero when Encryption = 0 | HCI command-encoding oracle |
| 32 | `CORE63-V3PC-10.8-02` | GAP §10.8 | a bonded device shall process an RPA | RPA resolution against the bond database |
| 33 | `CORE63-V3PC-1.23.3-01` | GAP §1.23.3 | Encrypted Data Key Material read requirement | EAD key-material acquisition path |
| 34 | `CORE63-V3PA-7.6-06` | L2CAP §7.6 | unencrypted data on a connectionless channel must be ignored | fail-closed receive path |
| 35 | GAP §10.7 / §10.8 privacy state machine | GAP | RPA timeout, address rotation, `no-matrix-row-cites-section` | privacy state-machine transition table |
| 36 | GATT §7.3 Database Hash recomputation triggers | GATT | state-machine; hash staleness after service change | hash invalidation on every mutating operation |
| 37 | GATT §7.1 Service Changed indication rules | GATT | per-connection state; which clients must be indicated | per-bond Service Changed matrix |
| 38 | ATT §3.2.11 EATT bearer rules | ATT | per-connection vs shared state | one-transaction-per-bearer legality |
| 39 | L2CAP §4 signalling packet field widths and RFU handling | L2CAP | wire representation | RFU/reserved-field rejection matrix |
| 40 | GAP §9 discoverability and connectability mode matrix | GAP | mandatory-for-interop; 3.4% covered layer | mode/procedure conformance table |

Items 35–40 are section-level entries rather than single sentences: they name
regions where `no-matrix-row-cites-section` is dense enough that a single test
case is not the right unit of work.

---

## 6. Specification documents (task 5)

### 6.1 Status: the document gap is closed

`/usr/src/bluetooth-specs` now contains, in addition to the Core Specification
and Assigned Numbers it already held:

| File | Version | Retrieved | SHA-256 (PDF) |
| --- | --- | --- | --- |
| `MshPRT_v1.1.1.pdf` / `.txt` | Mesh Protocol 1.1.1 (2025-11-03) | 2026-09-08 | `11f6c5d5…52af63c7` |
| `MshMDL_v1.1.1.pdf` / `.txt` | Mesh Model 1.1.1 (2025-11-03) | 2026-09-08 | `df0615c5…cfca3e17` |
| `Device_Properties.pdf` / `.txt` | Device Properties (2026-02-04) | 2026-09-08 | `432f7769…d61e662` |
| `CSS_v15.pdf` / `.txt` | Core Specification Supplement v15 (2026-05-05) | 2026-09-08 | `43226d4a…5bb3fed8` |
| `HOGP_v1.1.pdf` / `.txt` | HID Over GATT Profile 1.1 (2025-08-05) | 2026-09-08 | `d07f49d9…166a7d40` |
| `HOGP_v1.2.pdf` / `.txt` | HID Over GATT Profile 1.2 (2026-04-21) | 2026-09-08 | `dd35da33…f13bfce3` |
| `HIDS_v1.1.pdf` / `.txt` | HID Service 1.1 (2026-04-21) | 2026-09-08 | `6aedf9a0…cf1a9982` |
| `GATT_Specification_Supplement.txt` | render of the PDF already in tree | 2026-09-08 | (PDF) `1819c5b9…a49f5a574` |

Full URLs, spec-page links, and untruncated checksums are in
`bluetooth-specs/README.md`. Every document came from the Bluetooth SIG's own
public download hosts (`files.bluetooth.com`, and the SIG blob store
`btprodspecificationrefs.blob.core.windows.net` that the GATT Specification
Supplement already came from). No account, licence click-through or other
access control was involved, and no third-party mirror was used.

All `.txt` renders use `pdftotext -layout`, the method verified to reproduce
`Core_Specification_6_3.txt` byte for byte (pages 200-202 re-rendered and
compared: exact under `-layout`, mismatched under the default and `-raw`
modes). Tool: poppler `pdftotext` 26.04.0.

### 6.2 Which mesh version the code actually implements

The code's own comments disagree — 215 sites write `MshPRT_v1.1`, 45 write
`MshMDL_v1.1`, and only a handful write 1.1.1. The disagreement is cosmetic,
and the feature set settles it. Every one of the additions that distinguish
Mesh 1.1 from Mesh 1.0 is present in `lib/libmesh`:

| Mesh 1.1 addition | Evidence in tree |
| --- | --- |
| Directed Forwarding | `lib/libmesh/mesh_df.c`, `mesh_df.h`; 15 files reference it |
| Private Beacons | 11 files; `mesh_beacon.h` encodes the 1.1 RFU bit rules |
| Solicitation PDU / RPL | 3 files |
| Large Composition Data | 5 files |
| Remote Provisioning | 4 files (`mesh_remote_prov.c`) |
| SAR Transmitter/Receiver states | 8 files; `mesh_sim.c` cites `MshPRT_v1.1` §§4.2.29-4.2.30 |

There is no 1.0-only stack here. **1.1.1 is the correct document**: the SIG
publishes 1.1.1 as the errata-corrected release of the 1.1 feature set, with
no functional additions over 1.1, so it is simultaneously the version the "1.1"
comments mean and the version the "1.1.1" comments name. Both `MshPRT` and
`MshMDL` 1.1.1 are the current adopted releases; the SIG publishes no separate
errata or corrigenda document for them — the corrections are folded into the
1.1.1 text itself. Remote Provisioning is **not** a separate deliverable: it is
Mesh Protocol 1.1.1 §4, so `mesh_remote_prov.c`'s citation of a standalone
"Mesh Remote Provisioning 1.1" document is a citation error.

The remaining action is cosmetic: sweep the 260 `_v1.1` citations to `_v1.1.1`.

### 6.3 HOGP: the cited version does not exist

Three matrix rows and several code comments cite "HID over GATT Profile
1.1.1". **The SIG has never published a HOGP 1.1.1.** The adopted versions are
1.0, 1.1 and 1.2. The substantive citations in the code (§4.11 Boot Protocol
Mode, §4.6 Report Reference) match HOGP **1.1**, which is what the pipeline
extracts. HOGP 1.2 is also in tree, for reference only, so the 1.1→1.2 delta
can be assessed later without a second retrieval; nothing extracts from it.

### 6.4 Advertising data

The Supplement is in tree at **v15**, the current adopted version. Six matrix
rows still cite "CSS v12". Coverage attribution matches on document family
rather than version, so those rows remain attributable, and
`spec_conf_generate_profile.sh` prints the skew on every run rather than
silently resolving it. Reconciling the six citations to v15 is a follow-up.

### 6.5 The new numbers

`spec_conf_generate_profile.sh` extracts 4,000 normative sentences from the
five in-scope documents and classifies them with the same rules the Core
pipeline uses — COVERED only when the requirement's *exact* section is cited by
a matrix row whose oracle is independent of the implementation.

| Document | Requirements | COVERED | UNCOVERED | NOT-APPLICABLE | Covered % of applicable |
| --- | ---: | ---: | ---: | ---: | ---: |
| Mesh Protocol 1.1.1 (§§3-7) | 2,626 | 219 | 2,407 | 0 | 8.3% |
| Mesh Model 1.1.1 (§§2-6) | 1,170 | 8 | 1,161 | 1 | 0.7% |
| **Mesh total** | **3,796** | **227** | **3,568** | **1** | **6.0%** |
| Core Spec Supplement v15 (Vol 1 Part A, advertising data) | 44 | 3 | 41 | 0 | 6.8% |
| HID Over GATT Profile 1.1 (§§2-7) | 123 | 0 | 76 | 47 | 0.0% |
| HID Service 1.1 (§§2-3) | 37 | 5 | 24 | 8 | 17.2% |
| **All profile documents** | **4,000** | **235** | **3,709** | **56** | **6.0%** |

For comparison, the Core catalogue stands at 2,255 requirements: 842 COVERED,
1,228 UNCOVERED, 185 NOT-APPLICABLE (40.7% of applicable). Combined across
Core and profile documents the honest figure is **1,077 covered of 6,014
applicable requirements, 17.9%** — down from the 40.7% that could be quoted
while three quarters of the normative corpus was simply absent and unmeasurable.

Two results deserve to be read carefully rather than as scoreboard numbers:

* **HOGP 1.1 shows 0 COVERED, and that is correct.** 26 of its requirements sit
  in sections the matrix *does* cite (`§4.11`, `§§4.5-4.15`), but the citations
  name parent sections while the requirements live in subsections, so they
  classify as `ancestor-section-only-no-direct-citation`. The existing rule
  never promotes an ancestor citation to COVERED, and that rule is not relaxed
  here. Tightening the three HOGP rows to the subsections they actually assert
  is the cheapest coverage win in the whole matrix.
* **47 of HOGP's 123 requirements are NOT-APPLICABLE**, and this is a
  role/feature statement, not an excuse: 39 are the LE Audio HID ISO transport
  (HOGP §§5-6), which `blued` does not implement at all, and 7 are addressed to
  the HID Device, a role `blued` never plays — it is a HID Host that consumes a
  HID Service and never publishes one. The same rule marks 8 HIDS requirements
  NOT-APPLICABLE.

Mesh Model's 0.7% is the starkest gap in the tree. 1,161 uncovered normative
sentences across Generic, Sensor, Time/Scene and Lighting are asserted by
`mesh_generic_test`, `mesh_sensor_test` and `mesh_time_scene_test` only through
matrix rows that cite whole chapters.

### 6.6 Top uncovered mesh requirements by risk

Ranked by `spec_conf_rank_profile.awk`, which uses the defect-class weights of
the existing ranked gap list (wire representation 30, key material 30, state
machine 25, error-code selection 25, per-connection/subnet state 20, security
35, prohibition 15, mandatory support 20) plus a document weight that treats
Mesh Protocol as a security TCB (+20, the weight Vol 3 Part H carries) and Mesh
Model as a peer-visible wire surface (+15).

| # | Score | Requirement | Section | Risk classes | Substance |
| --- | ---: | --- | --- | --- | --- |
| 1 | 130 | `MSHPRT111-4.4.1.2.12-03` | §4.4.1.2.12 | wire, key, state, error | Config Node Identity Set handling |
| 2 | 130 | `MSHPRT111-4.4.1.2.14-01` | §4.4.1.2.14 | wire, key, state, error | Config Key Refresh Phase Get handling |
| 3 | 130 | `MSHPRT111-4.4.1.2.14-03` | §4.4.1.2.14 | wire, key, state, error | Config Key Refresh Phase Set handling |
| 4 | 130 | `MSHPRT111-4.4.11.2.3-03` | §4.4.11.2.3 | wire, key, state, error | PRIVATE_NODE_IDENTITY_SET handling |
| 5 | 130 | `MSHPRT111-6.7.1-11` | §6.7.1 | wire, state, per-connection, security | Directed Proxy Server DIRECTED_PROXY_CONTROL handling |
| 6 | 125 | `MSHPRT111-4.4.1.2.9-11` | §4.4.1.2.9 | wire, key, state, per-connection | Subnet bridge NetKey Index rules |
| 7 | 125 | `MSHPRT111-4.4.7.4.3-20` | §4.4.7.4.3 | wire, key, state, per-connection | Invalid NetKey Index status handling |
| 8 | 125 | `MSHPRT111-4.4.8.2.1-01/-02` | §4.4.8.2.1 | wire, key, state, per-connection | Directed Control state get/set |
| 9 | 125 | `MSHPRT111-4.4.8.2.2-01/-02` | §4.4.8.2.2 | wire, key, state, per-connection | Path Metric state get/set |
| 10 | 125 | `MSHPRT111-4.4.8.2.3-01` | §4.4.8.2.3 | wire, key, state, per-connection | Discovery Table Capabilities state |

The shape of this list is the finding. The top of the mesh gap list is not
exotic: it is the **Configuration Server message-handling matrix** —
key-refresh phase, node identity, subnet bridge, and the Directed Forwarding
configuration states — where a wrong status code or a missed state transition
is both wire-visible to every peer and directly security-relevant, because
these are the messages that move key material between phases. `mesh_cfg_v11.c`
and `mesh_df.c` are where this work lands.

### 6.7 What is still not covered by a document

The A2DP/AVDTP/AVRCP/CAP PDFs remain in tree, but nothing in `blued` or `meshd`
implements those profiles and no matrix row cites A2DP, AVDTP or AVRCP.

`GATT_Specification_Supplement.txt` now exists, so the four rows citing it are
machine-checkable in principle; no generator reads it yet. Extraction from the
Supplement and from `Device_Properties.txt` (Property IDs for the Sensor and
Lighting models) is the natural next increment.

## 7. Making it enforceable (task 6)

### The problem

`spec_traceability_audit.sh`, `spec_case_manifest_audit.sh` and
`check_generated_oracles.sh` run only from `make spec-traceability` and
`make spec-traceability-strict`. Neither target is a registered ATF case,
neither is in the Kyuafile, and neither runs in a normal `kyua test`. A
hand-edited oracle constant, a dropped requirement row, or a stale generated
header leaves the entire suite green.

### The fix

`spec_conf_traceability_test.c` registers eight ATF cases:

| Case | Gates | Skips when |
| --- | --- | --- |
| `requirements_matrix_wellformed` | 7-column schema, valid `authority`/`oracle_class`/`spec_source` enums, no implementation row claiming a spec source, narrow locator on every normative row, conformance-countable row count ≥ 120 | classified matrix not installed |
| `generated_requirements_catalogue_fresh` | `spec_conf_generate.sh --check` — the extracted catalogue, its coverage classification, and the ranked gap list all match the specification text | Core/Assigned sources absent |
| `generated_profile_catalogue_fresh` | `spec_conf_generate_profile.sh --check` — the Mesh Protocol, Mesh Model, Supplement, HOGP and HID Service catalogues, their coverage classification, and the ranked gap list all match the specification texts | profile sources absent |
| `generated_oracles_fresh` | `check_generated_oracles.sh` — `spec_core63_generated.h` and `spec_assigned_generated.h` still match the SIG text | Core/Assigned sources absent |
| `coverage_floor_not_regressed` | requirement count ≥ 2200, covered ≥ 800, and the three statuses partition the catalogue | generated coverage file not installed |
| `traceability_audit_gate` | `spec_traceability_audit.sh -q` | `kyua(1)` unavailable, or no Kyuafile beside the program |
| `case_manifest_gate` | `spec_case_manifest_audit.sh -q` | as above |
| `cited_documents_are_accounted_for` | every `absent:` document is one of the six known gaps — a *new* citation of a document nobody has fails | classified matrix not installed |

Skips are the mechanism that lets this ship: the SIG documents are local review
inputs and are not redistributed, so builders without them get honest skips
rather than spurious failures, while any builder that *has* them gets the gate.

### Required Makefile changes

These are reported, not applied (another agent owns the Makefile):

```make
# 1. Register the program.
ATF_TESTS_C+=	spec_conf_traceability_test

# 2. Install the scripts and catalogues next to the test program, or every
#    case above skips in an installed bluetooth-tests package.  bsd.test.mk
#    pins ${PACKAGE}FILES DIR to ${TESTSDIR}, which is what we want here.
${PACKAGE}FILES+=	spec_requirements.tsv
${PACKAGE}FILES+=	spec_test_references.tsv
${PACKAGE}FILES+=	spec_conf_requirements_proposed.tsv
${PACKAGE}FILES+=	spec_conf_requirements_generated.tsv
${PACKAGE}FILES+=	spec_conf_coverage_generated.tsv
${PACKAGE}FILES+=	spec_conf_gaps_ranked.tsv
${PACKAGE}FILESMODE_spec_traceability_audit.sh=	0555
${PACKAGE}FILES+=	spec_traceability_audit.sh
${PACKAGE}FILESMODE_spec_case_manifest_audit.sh=	0555
${PACKAGE}FILES+=	spec_case_manifest_audit.sh
${PACKAGE}FILESMODE_check_generated_oracles.sh=	0555
${PACKAGE}FILES+=	check_generated_oracles.sh
${PACKAGE}FILESMODE_spec_conf_generate.sh=	0555
${PACKAGE}FILES+=	spec_conf_generate.sh
${PACKAGE}FILES+=	generate_core63_oracles.awk
${PACKAGE}FILES+=	generate_assigned_oracles.awk
${PACKAGE}FILES+=	spec_conf_extract_requirements.awk
${PACKAGE}FILES+=	spec_conf_hci_scope.awk
${PACKAGE}FILES+=	spec_conf_coverage.awk
${PACKAGE}FILES+=	spec_conf_rank.awk
${PACKAGE}FILES+=	spec_conf_relabel.awk
${PACKAGE}FILESMODE_spec_conf_generate_profile.sh=	0555
${PACKAGE}FILES+=	spec_conf_generate_profile.sh
${PACKAGE}FILES+=	spec_conf_extract_profile_requirements.awk
${PACKAGE}FILES+=	spec_conf_coverage_profile.awk
${PACKAGE}FILES+=	spec_conf_rank_profile.awk
${PACKAGE}FILES+=	spec_conf_profile_requirements_generated.tsv
${PACKAGE}FILES+=	spec_conf_profile_coverage_generated.tsv
${PACKAGE}FILES+=	spec_conf_profile_gaps_ranked.tsv

# 3. Keep the hand-invoked targets; they are now a superset shortcut.
```

### Kyuafile

`bsd.test.mk` generates the Kyuafile from `ATF_TESTS_C`, so change (1) above is
the only Kyuafile change needed. Verify after the build that
`kyua list -k ${.OBJDIR}/Kyuafile | grep spec_conf_traceability_test` shows all
seven cases.

### One caveat

`traceability_audit_gate` and `case_manifest_gate` shell out to `kyua list`
against the same Kyuafile that is running them. Listing does not execute cases
— it runs each test program with `-l` — so this terminates, but it does make
those two cases proportional to the size of the suite. If that cost is
unacceptable, move them behind a `require.config` variable and run them in CI
only; the other five cases carry the drift protection and are cheap.

---

## 8. Proposed replacement matrix

`spec_conf_requirements_proposed.tsv` is a drop-in replacement for
`spec_requirements.tsv`, generated by `spec_conf_relabel.awk` so it is
reproducible. Columns 1–4 are byte-identical to the original; three columns are
appended:

* `authority` — `normative` | `implementation` | `mixed`
* `oracle_class` — `external` | `internal` | `mixed`
* `spec_source` — `in-tree` | `absent:<Document>[;<Document>…]` | `n/a`

Only rows with `authority=normative`, `oracle_class=external` and
`spec_source=in-tree` may be reported as specification conformance. That is 123
rows, not 316.

`spec_traceability_audit.sh` reads the file with
`while IFS="$tab" read -r requirement_id exact_reference selectors oracle`,
so the appended columns would be absorbed into `$oracle`. One line must change:

```sh
-while IFS="$tab" read -r requirement_id exact_reference selectors oracle; do
+while IFS="$tab" read -r requirement_id exact_reference selectors oracle \
+    authority oracle_class spec_source; do
```

and its summary line should report the countable subset rather than the row
count. That edit is deliberately not applied here — the file is shared with
concurrent work.

---

## 9. Files

Generators and catalogues (all under `tests/usr.sbin/bluetooth/blued/`):

| File | Role |
| --- | --- |
| `spec_conf_generate.sh` | driver; `--check` mode for drift |
| `spec_conf_extract_requirements.awk` | normative-sentence extraction, scope table |
| `spec_conf_hci_scope.awk` | HCI section scope derived from blued's opcodes |
| `spec_conf_coverage.awk` | COVERED / UNCOVERED / NOT-APPLICABLE classification |
| `spec_conf_rank.awk` | risk ranking of the uncovered set |
| `spec_conf_relabel.awk` | produces the proposed replacement matrix |
| `spec_conf_requirements_generated.tsv` | 2255 extracted requirements |
| `spec_conf_coverage_generated.tsv` | coverage classification |
| `spec_conf_gaps_ranked.tsv` | ranked gap list |
| `spec_conf_requirements_proposed.tsv` | proposed replacement for `spec_requirements.tsv` |
| `spec_conf_generate_profile.sh` | driver for the profile/supplement catalogues (`--check` for drift) |
| `spec_conf_extract_profile_requirements.awk` | normative-sentence extraction for Mesh/CSS/HOGP/HIDS |
| `spec_conf_coverage_profile.awk` | document-family coverage attribution |
| `spec_conf_rank_profile.awk` | risk ranking, Core weights plus document weights |
| `spec_conf_profile_requirements_generated.tsv` | 4,000 extracted profile requirements |
| `spec_conf_profile_coverage_generated.tsv` | their coverage classification |
| `spec_conf_profile_gaps_ranked.tsv` | ranked profile gap list |
| `spec_conf_traceability_test.c` | the eight ATF gates |

## 10. What to do next, in order

1. ~~Obtain the missing specifications.~~ **Done** (§6): Mesh Protocol 1.1.1,
   Mesh Model 1.1.1, Device Properties, CSS v15, HOGP 1.1 (and 1.2 for
   reference) and HID Service 1.1 are in tree with recorded provenance, and the
   GATT Specification Supplement is rendered to text. The follow-ups are
   citation hygiene, not acquisition: sweep the 260 `_v1.1` mesh citations to
   `_v1.1.1`, correct the "HOGP 1.1.1" citations to 1.1 (no such version
   exists), correct `mesh_remote_prov.c`'s standalone "Mesh Remote Provisioning
   1.1" citation to Mesh Protocol 1.1.1 §4, and reconcile the six "CSS v12"
   rows to v15.
2. Land `spec_conf_traceability_test.c` and the Makefile changes in §7 so drift
   fails the suite.
3. Adopt `spec_conf_requirements_proposed.tsv` and stop reporting 317/317.
4. Work the ranked list in §5, starting with the GATT error-code matrix
   (items 1–6) and the SMP key-size truncation rules (items 8–9).
5. Attack GAP (Vol 3 Part C), the 3.4%-covered layer, as a block rather than
   sentence by sentence.
