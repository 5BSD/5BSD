# Bazel migration: DTrace and security-audit review log

Last updated: 2026-10-26. This is an open review ledger, not a coverage certificate.

## Review required for each migrated component

- Preserve existing provider sources, probe macros, compile options, regular/PIC
  object rewriting, provider linkage and build-option behavior.
- Preserve existing audit sources, event identifiers, conditional definitions,
  dependencies and delivery/error behavior. DTrace and ordinary logging do not
  substitute for security audit events.
- Record missing instrumentation as a candidate with a concrete operation and
  rationale. An absence of component-specific probes is not itself a defect:
  syscall, scheduler, filesystem or shared-library probes may already cover it.
- Verify configured Bazel actions and final artifacts, then record separate
  runtime evidence of probe firing and audit delivery. A source grep or a BUILD
  file is insufficient to close a runtime finding.
- Include kernel and modules: SDT/provider definitions, CTF where required,
  module loading/unloading and enabled/disabled configurations. These migrations
  and runtime checks remain pending.
- Do not put credentials, private keys or sensitive payloads into probe/audit
  arguments. Review disabled-probe overhead and enabled tracing costs for hot paths.

## Findings and follow-up

| Component | Finding | Status / next evidence |
|---|---|---|
| libssh | sshkeys provider is declared; regular/PIC rewrites and static anchor are wired. | Build/symbol parity recorded in README; broader live probe firing remains open. |
| libpam and migrated PAM modules | Existing pamchain and module provider rules are present. | Build checks exist; qualify live success/failure events during isolated authentication tests. |
| chmod, chown | Existing modechange/fileowner providers are wired into native targets. | Check actual events and argument semantics; audit policy review remains open. |
| id | USE_BSM_AUDIT follows the typed audit option. | Check enabled/disabled runtime behavior; this flag alone is not proof of event emission. |
| sshd-session | Make includes audit.c/audit-bsm.c/audit-linux.c and BSM definitions conditionally. | Native server migration pending: preserve these conditions and qualify successful/failed authentication, session start/end and event delivery. |
| login, su, passwd | Native BUILD targets absent in this review. login/su contain existing audit paths. | Inventory each program's events and preserve them during migration; inspect passwd/PAM event responsibility separately. |
| libc | BUILD currently exports Versions.def only; Make declares nameres provider. | Pending libc migration, not a demonstrated provider omission from a native libc build. |
| devd | BUILD currently installs NVMe configuration only; Make declares devd provider. | Pending executable migration; preserve device-event probes. |
| rtld-elf | BUILD provides headers/support source, not a migrated loader; Make declares rtldtrace provider. | Pending loader migration; preserve lazy-load DTrace behavior and loader events. |
| rc.d | Native package fragment covers ZFS scripts, not the complete rc.d inventory. | Audit startup/configuration scripts remain a whole-system packaging gate. |
| SSH agent/key helpers | Key-provider coverage in libssh is not proof of helper-specific lifecycle or policy events. | Review key add/remove/use, provider loading and access-denial observability without exposing key material. No confirmed omission yet. |
| Kerberos support/com_err/profile, CBOR/FIDO | Recent component migrations do not establish protocol/device-operation observability. | Review at the Kerberos authentication and FIDO operation boundaries; do not add redundant low-level events just to populate a checklist. |
| Capability daemons, mac_abac, openES, Capsule/Switchboard | Complete native target/event review not performed by this scan. | Inventory service decisions, denial/delivery paths and existing probes before marking their migration qualified. |
| Kernel/modules/drivers | Native migration and runtime coverage incomplete. | Review SDT, CTF, syscall/audit hooks and module lifecycle; verify on the matching test kernel. |

## Initial retrospective source triage

Scanned directories containing both BUILD.bazel and Makefile for direct Make
DTrace/provider/audit markers. Found 95 candidates. The table below records this
bounded scan; it does not cover inherited Make includes, all source-level hooks,
macro expansion, generated metadata or transitive runtime behavior. Some BUILD
files are only exports/install fragments, not converted programs. No row is
marked runtime-qualified by this scan. Components without markers still require
semantic review; they are not automatically exempt or defective.

The four rows without direct Bazel markers were inspected above (libc, devd,
rtld-elf, rc.d): each is a partial export/install target. The remaining markers
are triage evidence only, not proof of complete preservation.

| Component | Direct Bazel marker | Next review |
|---|---|---|
| `bin/cat` | Present | Configured graph/artifact and runtime review |
| `bin/chflags` | Present | Configured graph/artifact and runtime review |
| `bin/chmod` | Present | Configured graph/artifact and runtime review |
| `bin/cp` | Present | Configured graph/artifact and runtime review |
| `bin/cpuset` | Present | Configured graph/artifact and runtime review |
| `bin/dd` | Present | Configured graph/artifact and runtime review |
| `bin/df` | Present | Configured graph/artifact and runtime review |
| `bin/getfacl` | Present | Configured graph/artifact and runtime review |
| `bin/kenv` | Present | Configured graph/artifact and runtime review |
| `bin/kill` | Present | Configured graph/artifact and runtime review |
| `bin/ln` | Present | Configured graph/artifact and runtime review |
| `bin/mkdir` | Present | Configured graph/artifact and runtime review |
| `bin/mv` | Present | Configured graph/artifact and runtime review |
| `bin/pwait` | Present | Configured graph/artifact and runtime review |
| `bin/realpath` | Present | Configured graph/artifact and runtime review |
| `bin/rm` | Present | Configured graph/artifact and runtime review |
| `bin/rmdir` | Present | Configured graph/artifact and runtime review |
| `bin/setfacl` | Present | Configured graph/artifact and runtime review |
| `bin/sleep` | Present | Configured graph/artifact and runtime review |
| `bin/sync` | Present | Configured graph/artifact and runtime review |
| `bin/timeout` | Present | Configured graph/artifact and runtime review |
| `cddl/lib/libdtrace` | Present | Configured graph/artifact and runtime review |
| `cddl/usr.sbin/dtrace` | Present | Configured graph/artifact and runtime review |
| `cddl/usr.sbin/lockstat` | Present | Configured graph/artifact and runtime review |
| `cddl/usr.sbin/plockstat` | Present | Configured graph/artifact and runtime review |
| `lib/libarchive` | Present | Configured graph/artifact and runtime review |
| `lib/libc` | Absent; partial target inspected | Configured graph/artifact and runtime review |
| `lib/libcasper/libcasper` | Present | Configured graph/artifact and runtime review |
| `lib/libcasper/services/cap_dns` | Present | Configured graph/artifact and runtime review |
| `lib/libcasper/services/cap_fileargs` | Present | Configured graph/artifact and runtime review |
| `lib/libcasper/services/cap_grp` | Present | Configured graph/artifact and runtime review |
| `lib/libcasper/services/cap_net` | Present | Configured graph/artifact and runtime review |
| `lib/libcasper/services/cap_netdb` | Present | Configured graph/artifact and runtime review |
| `lib/libcasper/services/cap_pwd` | Present | Configured graph/artifact and runtime review |
| `lib/libcasper/services/cap_sysctl` | Present | Configured graph/artifact and runtime review |
| `lib/libcasper/services/cap_syslog` | Present | Configured graph/artifact and runtime review |
| `lib/libfetch` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/libpam` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_chroot` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_deny` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_exec` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_ftpusers` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_group` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_guest` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_lastlog` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_login_access` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_nologin` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_permit` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_radius` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_rhosts` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_rootok` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_securetty` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_self` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_ssh` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_tacplus` | Present | Configured graph/artifact and runtime review |
| `lib/libpam/modules/pam_unix` | Present | Configured graph/artifact and runtime review |
| `lib/libthr` | Present | Configured graph/artifact and runtime review |
| `lib/libutil` | Present | Configured graph/artifact and runtime review |
| `libexec/rc/rc.d` | Absent; partial target inspected | Configured graph/artifact and runtime review |
| `libexec/rtld-elf` | Absent; partial target inspected | Configured graph/artifact and runtime review |
| `packages/dtrace` | Present | Configured graph/artifact and runtime review |
| `sbin/devd` | Absent; partial target inspected | Configured graph/artifact and runtime review |
| `sbin/kldload` | Present | Configured graph/artifact and runtime review |
| `sbin/kldstat` | Present | Configured graph/artifact and runtime review |
| `sbin/kldunload` | Present | Configured graph/artifact and runtime review |
| `sbin/mount` | Present | Configured graph/artifact and runtime review |
| `sbin/sysctl` | Present | Configured graph/artifact and runtime review |
| `sbin/umount` | Present | Configured graph/artifact and runtime review |
| `secure/lib/libssh` | Present | Configured graph/artifact and runtime review |
| `share/dtrace` | Present | Configured graph/artifact and runtime review |
| `usr.bin/brandelf` | Present | Configured graph/artifact and runtime review |
| `usr.bin/du` | Present | Configured graph/artifact and runtime review |
| `usr.bin/env` | Present | Configured graph/artifact and runtime review |
| `usr.bin/fsync` | Present | Configured graph/artifact and runtime review |
| `usr.bin/gzip` | Present | Configured graph/artifact and runtime review |
| `usr.bin/id` | Present | Configured graph/artifact and runtime review |
| `usr.bin/limits` | Present | Configured graph/artifact and runtime review |
| `usr.bin/lockf` | Present | Configured graph/artifact and runtime review |
| `usr.bin/logger` | Present | Configured graph/artifact and runtime review |
| `usr.bin/mkfifo` | Present | Configured graph/artifact and runtime review |
| `usr.bin/mktemp` | Present | Configured graph/artifact and runtime review |
| `usr.bin/pathchk` | Present | Configured graph/artifact and runtime review |
| `usr.bin/renice` | Present | Configured graph/artifact and runtime review |
| `usr.bin/split` | Present | Configured graph/artifact and runtime review |
| `usr.bin/stat` | Present | Configured graph/artifact and runtime review |
| `usr.bin/tail` | Present | Configured graph/artifact and runtime review |
| `usr.bin/tar` | Present | Configured graph/artifact and runtime review |
| `usr.bin/tee` | Present | Configured graph/artifact and runtime review |
| `usr.bin/touch` | Present | Configured graph/artifact and runtime review |
| `usr.bin/truncate` | Present | Configured graph/artifact and runtime review |
| `usr.bin/vmstat` | Present | Configured graph/artifact and runtime review |
| `usr.bin/wc` | Present | Configured graph/artifact and runtime review |
| `usr.sbin/chown` | Present | Configured graph/artifact and runtime review |
| `usr.sbin/daemon` | Present | Configured graph/artifact and runtime review |
| `usr.sbin/jail` | Present | Configured graph/artifact and runtime review |

## Subsequent component reviews

- 2026-10-26, krb5/include/krb5: generated public/error/plugin-header installation.
  No executable/runtime hook changed. Header parity with Make is recorded in
  README; no runtime DTrace/audit coverage is inferred. Kerberos authentication
  event review remains pending with the protocol libraries and server migration.

- 2026-10-26, krb5/lib/crypto: inspected maintained Makefiles and vendor crypto C
  sources for DTrace/provider declarations and audit calls; none found in this
  focused scan. Native source-path/ABI checks and three vector tests are recorded
  in README. No runtime hooks were added or removed. Review authentication-event
  ownership with the core protocol/server migration; avoid exposing keys or
  intermediate cryptographic material through new events.

- 2026-10-26, core krb5/lib/krb5 (migration in progress): native sources retain
  os/trace.c, including KRB5_TRACE and trace callbacks; no DISABLE_TRACING define
  was introduced. This is source-level evidence only. MIT diagnostic tracing is
  distinct from DTrace probes and security audit events. Runtime tracing and
  authentication-event delivery remain pending with protocol/server qualification.

- 2026-10-26, krb5/lib/gssapi (migration in progress): source inventory retains
  krb5/acquire_cred.c and TRACE_GSS_CLIENT_KEYTAB_FAIL. The focused scan found
  this diagnostic trace event; it does not establish complete event coverage
  or security-audit delivery. Runtime tracing, failed/successful authentication
  and protocol integration remain pending.

- 2026-10-26, pam_ksu: native declaration uses pam_module with the maintained
  pam_ksu_provider.d and pam_ksu_probes.h, retaining authenticate and setcred
  probe call sites. The independent Make reference completed; native provider
  object comparison and runtime probe/audit delivery are not yet qualified.

- 2026-10-26, MIT pam_krb5: native sources retain module/auth.c and
  pam-util/logging.c, including pam_syslog authentication and diagnostic paths.
  No direct DTrace provider was found in the focused module/Make scan. Logging
  is not evidence of security-audit delivery. Runtime log/audit delivery and
  authentication flows remain pending; all 20 source/copy inputs match Make.

- 2026-10-26, SSH server dependency review: sshd-session's maintained Make
  inventory includes audit.c, audit-bsm.c and audit-linux.c; MK_AUDIT adds
  USE_BSM_AUDIT, HAVE_GETAUDIT_ADDR and libbsm. MK_BLOCKLIST_SUPPORT adds
  blocklist.c/libblocklist, and MK_TCP_WRAPPERS adds libwrap. MK_DTRACE retains
  sshauth_provider.d with its static anchor and WITH_COVERAGE_DTRACE. The provider
  declares decision, method-start and method-done probes. Native libbsm, libwrap
  and libblocklist are still absent and must precede a qualified default server
  graph. No feature is disabled to avoid those dependencies. Server graph,
  generated probe artifacts, audit delivery and live authentication remain open.

- 2026-10-26, libblocklist: native declarations retain lib/bl.c,
  lib/blocklist.c and port/vsyslog_r.c with their maintained configuration.
  This is the reporting library used by services; it does not establish daemon
  receipt, firewall enforcement or audit-event delivery. Native artifact and
  IPC runtime qualification remain pending.

- 2026-10-26, authentication r2 follow-up: retained package/ABI comparisons now
  pass for pam_ksu, pam_krb5, GSSAPI and libblocklist. pam_ksu's comparison retains
  the probe symbol checks; generated numeric probe IDs are normalized, while
  raw defined/undefined probe sets must agree. This does not demonstrate live
  probe firing or audit event delivery. libblocklist IPC/daemon enforcement
  remains untested. Earlier entries describe their state at the time of review.

- 2026-10-26, libbsm: native declarations now retain all 15 maintained library
  source paths, including audit submission, token construction and wrappers.
  The vendor token fixture generator is a separate non-installed build target.
  It is not evidence of successful kernel audit submission or daemon receipt.
  Native build, format/runtime comparison and live audit integration remain
  pending. libwrap and the full native SSH server graph remain outstanding.

- 2026-10-26, libbsm follow-up: native build, source inventory, installation,
  static symbols and shared ABI now match the Make reference. The vendor token
  generator also builds. Runtime token checks, kernel audit submission and
  audit daemon delivery remain unqualified; package/ABI parity does not prove
  that security events are emitted or persisted.

- 2026-10-26, libwrap: all 20 native sources match the Make compile inventory.
  The focused source review retains refuse.c denial syslog calls, diag.c
  diagnostics and hosts_access.c matching diagnostics. These log paths are
  not proof of audit subsystem integration. Live allow/deny decisions and log
  delivery remain untested. No new event provider was introduced by migration.

- 2026-10-26, SSH listener: all 14 native source inputs match Make. This is the
  listener only; sshd-session's PAM, BSM audit, blocklist and sshauth DTrace
  provider remain required separate integration work. No server runtime or
  authentication/audit event delivery is claimed from this source inventory.

- 2026-10-26, sshd-session native graph: all 42 C source paths match Make,
  including audit-bsm.c, auth-pam.c and blocklist.c. The sshauth provider has
  declared native header generation and object rewriting with its static
  anchor. The first build passed installation checks but callback exports
  differed; alwayslink now preserves direct-object semantics and requalification
  is in progress. This source/build evidence does not establish live DTrace
  probe firing, PAM log delivery, kernel BSM audit delivery or blocklist actions.

- 2026-10-26, SSH session r2: callback exports now match Make. Generated
  sshauth provider header bytes and the retained provider anchor, DOF lifecycle
  routines and all three probe/enabled symbols match. The isolated startup and
  configuration checks pass with native component libraries and the common
  source SDK foundation. These checks do not trigger authentication or prove
  DTrace firing, security audit persistence or blocklist actions; those remain
  explicit integration gates.

- 2026-10-26, sshd-auth: all 46 Make C sources are retained, including audit,
  PAM, blocklist and platform sandbox code. Native header generation and probe
  rewriting retain the sshauth provider pipeline. Package/ABI comparisons pass;
  authentication, sandbox enforcement, live probes and audit delivery still
  require integration qualification. Startup-only ATF checks are now maintained
  for all three SSH server executables and are being run through Bazel.

- 2026-10-26, praudit/auditreduce/audit: native source inventories retain the
  maintained OpenBSM programs and libbsm calls. Package/debug/ABI comparisons
  pass. Praudit's ten existing fixture/error behaviors pass with native and Make
  component libraries. This proves decoding behavior for those fixtures, not
  live event production, kernel audit controls or daemon persistence. Those
  runtime gates remain open, as do auditreduce selection checks.

- 2026-10-26, auditreduce: ten selection/inversion/date cases pass against the
  maintained one-record fixture using native and Make components. This is
  offline trail processing; audit controls and daemon persistence are not
  exercised. Native libauditd is in progress and retains auditd_lib.c, but no
  daemon lifecycle or live event delivery claim follows from that declaration.

- 2026-10-26, libauditd/auditd: private library package and ABI parity pass.
  The daemon graph retains auditd.c, audit_warn.c and auditd_fbsd.c, including
  its syslog paths and the BSM control library. Configuration modes/manuals and
  daemon ABI match Make; full directory inventory recheck is pending. Live
  lifecycle, trail rotation, warning execution and persistence have not been
  exercised. No new provider or event coverage claim is made.

- 2026-10-26, libusb: all eight maintained C sources and versioned ABI are
  preserved; component installation and symbol comparisons pass. No USB I/O or
  hotplug events have been exercised. Probe/event coverage review for device
  lifecycle and transfer errors remains pending with the hardware integration
  work; the migration does not establish new tracing or audit coverage.

- 2026-10-26, usbconfig/usbdump: maintained source inventories, package/ABI and
  help/startup parity pass. A focused source scan found no direct DTrace/SDT,
  syslog or audit calls in these program C files. Device reset, configuration
  changes, firmware operations and capture access are candidates for a later
  observability/security-audit review; absence alone does not establish a
  missing-event requirement. Live hardware behavior remains unqualified.

- 2026-10-26, route: native route.c/show.c/route_netlink.c and generated keyword
  inventory match Make. IPv4/IPv6 loopback queries pass; route changes and
  monitoring are not exercised. Audit/tracing review of route mutation and
  routing-table/jail selection remains pending, including kernel-side event
  coverage. Read-only query parity does not establish that event coverage.

- 2026-10-26, mount_nullfs/mount_unionfs: maintained sources and package/ABI
  comparisons pass. Only argument rejection was exercised, with no nmount call.
  Review still needs to establish coverage when these helpers are invoked
  directly rather than through mount(8), including kernel audit events and
  mount-operation probes. Existing mount(8) provider preservation alone does
  not establish direct-helper event coverage.

### libkiconv review (2026-10-26)

The four migrated C sources retain the existing sysctl interfaces for driver
and charset listing and kern.iconv.add. A focused source scan found no direct
DTrace/SDT probes, syslog calls or audit calls in these sources. This is not
proof of missing kernel audit coverage: review kern.iconv.add authorization and
kernel event delivery with the mount callers before recommending new events.
No conversion table was changed on the host. Native/Make source, installation
and ABI comparisons are retained in bazel-kiconv-20261026 under /usr/obj/usr/src;
live syscall/audit/probe behavior remains pending.

### CD9660/MS-DOS mount helper follow-up (2026-10-26)

Native targets preserve each helper's source and libkiconv/libutil dependencies.
Review must cover nmount, optional iconv kernel-module loading and conversion
table registration through libkiconv. Startup/argument checks do not exercise
these paths. Kernel audit delivery and mount(8) versus direct-helper tracing
remain pending; no new probes or audit calls were invented to satisfy migration
checks. Evidence is retained at bazel-kiconv-mounts-20261026 under /usr/obj/usr/src.

### mount_virtiofs (2026-10-26)

The migrated helper uses sysctl tag discovery, opens a virtiofs device read/write
and passes the descriptor to nmount. Focused source inspection found no direct
DTrace/SDT, audit or syslog calls. Review kernel mount audit events and transport
session tracing before proposing additional instrumentation; usage-only tests
do not exercise those paths. No device or mount operation occurred on the host.

### mount_nfs and shared mounttab.c (2026-10-26)

Both Make-selected sources are compiled natively with the maintained NFS define.
The shared mount-table source retains syslog errors for open/write/remove,
allocation and malformed entries. Focused inspection found no direct DTrace/SDT
or audit calls in these two sources. Mount(8) tracing and kernel NFS/mount audit
coverage must be assessed together before adding instrumentation. Protocol,
authentication, retry/reconnect and mount-table failure paths remain untested;
argument checks exit before module loading or networking.

### rpc.umntall (2026-10-26)

Native build retains rpc.umntall.c and mounttab.c. Shared mount-table syslog
reporting is preserved; focused inspection found no direct audit/DTrace/SDT
calls in rpc.umntall.c. RPC notifications, mount-record expiry and persistence
need isolated functional tests and an audit-event review. Only invalid-option
startup was executed; the no-argument path is state-changing and was excluded.

### showmount and nfsstat (2026-10-26)

Focused inspection of both migrated C sources found no direct DTrace/SDT,
audit or syslog calls. showmount performs RPC enumeration; nfsstat observes
kernel statistics and has a counter-reset option. Review counter-reset audit
expectations and existing kernel instrumentation separately from ordinary
read-only statistics. Invalid-option tests preserve host state and do not
qualify RPC delivery, statistics output or audit coverage.

### mountd export reload provider (2026-10-26)

The native graph preserves exports:reload-start and reload-done, their enabled
checks, static anchor and DOF lifecycle. Generated header bytes match Make;
linked-symbol evidence is retained at bazel-mountd-r2-20261026. Existing syslog
reporting is unchanged. Live export reload probes and kernel export/audit events
remain unqualified. Direct startup is excluded because PID-file creation precedes
option validation; qualify service behavior in an isolated environment.

### nfsd and nfsuserd (2026-10-27)

Both source inventories and existing syslog paths are retained. Focused source
inspection found no direct DTrace/SDT or audit calls. Review existing kernel
NFS events together with server registration, stable restart, identity mapping
and administrative mutation paths before recommending new events. Neither
daemon was executed; nfsuserd can load nfscommon before parsing arguments.
Build/package parity does not establish service or audit-event delivery.

### rpcinfo (2026-10-27)

The native source preserves PORTMAP and existing query/mutation paths. Focused
inspection found no direct DTrace/SDT, audit or syslog calls. Distinguish ordinary
RPC queries from registration deletion when reviewing event requirements, and
inspect rpcbind's authorization/audit behavior before proposing instrumentation.
Only invalid-option startup ran; no RPC request or registration change occurred.

### rpcbind (2026-10-27)

All ten maintained C sources are retained, including security and warmstart.
Focused inspection found no direct DTrace/SDT or audit calls. Existing logging
and wrapper authorization remain in the source graph. Review registration
changes, forwarding, access denials and persisted warm-start state against
kernel and service audit coverage. Build/ABI comparisons establish neither
network authorization behavior nor event delivery; no service was started.

### NFS administration utilities (2026-10-27)

Native graphs retain nfsdumpstate, nfsrevoke, pnfsdsfile, pnfsdscopymr and
pnfsdskill sources. Review kernel NFSSVC_ADMINREVOKE and NFSSVC_PNFSDS audit
coverage together with pNFS file-attribute mutations. Distinguish read-only
state dumps from revocation, data-server removal and migration. Current checks
exercise only early errors; no administrative event delivery is qualified.
Source review also noticed pnfsdskill's existing usage text names pnfsdsfile;
that pre-existing diagnostic issue is preserved, not silently fixed for parity.

### nfscbd and nfsdtop (2026-10-27)

nfscbd's native graph retains its callback-service source. Kernel NFSCBD and
CBADDSOCK paths need runtime/audit qualification; startup was not attempted.
nfsdtop's complete installed script matches Make bytes, including FBT probes for
nfsrvd_read/write and nfsvno_read/write. Live probe availability, kernel structure
layouts, filter behavior and output processing remain untested. The script's
preserved DTrace code is not evidence that its probes work on the host kernel.

### file and libmagic (2026-10-27)

The native graphs preserve file.c, all 22 library sources and the seven-source
execution-platform magic compiler. Focused source/Make inspection found no direct
DTrace/SDT or audit submission integration. Content classification alone does not
establish a missing security audit requirement; review applications using libmagic
at authorization boundaries for their own decision/event logging. The 83 upstream
fixture passes exercise classification, not kernel audit delivery or probe coverage.

### whereis (2026-10-27)

Maintained source/header are retained with no direct DTrace/SDT or audit APIs
found by focused inspection. This read-only lookup utility has no newly identified
privileged decision requiring application audit integration. Its existing man and
locate command construction uses query strings in popen commands; review shell
quoting and helper lookup separately before claiming robust arbitrary-query
handling. Current qualification covers controlled binary lookup with explicit
directory lists, so neither helper execution nor event delivery was exercised.

### tsort and what (2026-10-27)

Maintained single-source implementations are retained. Focused source inspection
found no direct DTrace/SDT or audit submission calls. These graph-ordering and
identifier-extraction utilities introduce no identified privileged authorization
decision. Tests cover output and exit behavior, not syscall audit or tracing.
Existing tsort cycle diagnostics remain in source; quiet-cycle tests do not
qualify their delivery. No probes or audit hooks were removed for this migration.

### soelim (2026-10-27)

The maintained source is retained; focused inspection found no direct DTrace/SDT
or audit submission APIs. Include expansion reads input-selected paths without
introducing privileged authorization. Callers processing untrusted documents
must choose appropriate filesystem access; migration tests establish include
resolution and diagnostics, not sandbox confinement or audit event coverage.
No probe or audit implementation was removed.

### unifdef and unifdefall (2026-10-27)

The maintained conditional-processing source and wrapper script are retained.
Focused C/header inspection found no direct DTrace/SDT or audit submission APIs.
The current tests exercise text transformation, not filesystem mutation options
or wrapper subprocesses. No privileged authorization boundary requiring a new
application audit hook was identified. unifdefall's compiler and shell-helper
runtime coverage remains pending; byte-identical packaging is not that evidence.

### banner (2026-10-27)

Maintained rendering/font source is unchanged. Focused inspection found no direct
DTrace/SDT or audit submission APIs. No privileged authorization boundary was
identified in this text-rendering utility. Its existing -d/-t debugging modes are
not DTrace probes and were not qualified in the six rendering/width comparisons.

### calendar (2026-10-27)

All eleven maintained sources and native libutil dependency are retained. Focused
calendar-source inspection found no direct DTrace/SDT or audit submission APIs.
Native libutil retains its existing configured logincap provider. Review calendar
-a user enumeration, setusercontext transitions and mail delivery together with
libutil/kernel audit coverage before qualifying service use. Current explicit-file
runtime cases do not exercise those operations or establish probe/event delivery.

### compress and uncompress (2026-10-27)

Both maintained sources and alias behavior are retained. Focused inspection found
no direct DTrace/SDT or audit submission APIs. File modes can replace/remove input
files; current tests check that behavior only on isolated fixtures. Kernel file
operation audit coverage and broader overwrite/permission/error behavior remain
separate concerns. No probes or audit paths were removed during migration.

### file2c (2026-10-27)

The maintained one-source byte-to-C converter is retained. Source inspection
shows plain stdin/stdout formatting with no direct probe or audit submission
integration. The generator dependency head retains Capsicum protections; its
current host/SDK assertion was preserved and recorded as a qualification failure.
No protection was removed to obtain passing generated-fixture tests.

### ctags (2026-10-27)

All seven maintained parser/output sources are retained. Focused inspection found
no direct DTrace/SDT or audit submission APIs. Tag-file writes were exercised only
in isolated test directories. Append/update subprocess behavior and non-C parsers
remain unqualified. Existing usage advertises -v although both native and Make
binaries reject it; record for a separate source correctness fix.

### indent (2026-10-27)

All maintained parser/formatter sources are retained. Focused inspection found
no direct DTrace/SDT or audit submission APIs. Current tests use stdin/stdout
formatting with explicit profile policy; backup creation and file replacement
remain unqualified. These formatting results establish no syscall audit coverage.

### bsdiff and bspatch (2026-10-27)

Maintained patch-generation/application sources and bspatch Capsicum entry and
rights limits are retained. Focused inspection found no direct DTrace/SDT or audit
submission hooks. Patch application writes the caller-selected output; successful
isolated cross-applications establish neither patch authenticity nor updater
policy enforcement. Future updater integration must authenticate inputs and audit
its own authorization decisions. Malformed-patch cleanup/error paths remain open.

### caesar and rot13 (2026-10-27)

Maintained rotation source and shell wrapper are retained. Focused inspection
found no direct DTrace/SDT or audit submission APIs; no privileged authorization
boundary is introduced by this text transformation. Explicit rotations are
qualified, while automatic detection and installed wrapper invocation remain open.

### bsdiff/bspatch native test follow-up (2026-10-27)

The four ordinary patch workflows now execute in native Bazel cc_test targets.
No production sources or Capsicum checks changed. Existing absence of direct
DTrace/audit hooks is unchanged; these tests do not establish kernel syscall
audit coverage or authenticated updater authorization.

### enigma / crypt (2026-10-27)

Focused source inspection found no direct DTrace/SDT or audit submission hooks.
The legacy cipher and key-input behavior are unchanged. The manual already warns
about its cryptographic limitations; migration tests establish compatibility,
not secure encryption. Key prompting and I/O failures remain unqualified. This
unprivileged stream utility introduces no new authorization decision; general
syscall audit coverage still needs system qualification.

### getent (2026-10-27)

Focused source inspection found no direct DTrace/SDT or audit submission hooks.
The native target retains libc NSS interfaces without replacing database lookup
with fixtures or compiled-in accounts. Deterministic interface tests and separate
host NSS comparisons pass; password lookup, remote NSS and system audit behavior
remain unqualified. getent performs queries, not authentication decisions; audit
requirements for sensitive database access must be evaluated at the service or
system boundary rather than inferred from these output comparisons.

### ipcs (2026-10-27)

The maintained ipcsnapshot provider has query-start and query-done probes around
sysctl snapshot queries. Native generation and final DOF presence are verified
with DTrace enabled; disabled builds exclude the provider as Make does. No probe
was removed. Source inspection found no direct audit submission hooks. Live probe
firing, kvm/core-file access coverage, jail views and system syscall auditing
remain unqualified; read-only limit-query parity does not establish those paths.

### dtc (2026-10-27)

Focused inspection found no direct DTrace/SDT or audit submission hooks in the
maintained compiler sources. Native migration preserves those sources and their
C++ options. Input compilation and binary output parity are checked; included
file access, parser failures and board integration remain unqualified. This
compiler introduces no new privileged authorization policy. Kernel/driver probe
preservation is a separate obligation when its generated trees enter board builds.

### elfctl (2026-10-27)

Focused inspection found no direct DTrace/SDT or audit submission hooks. The tool
can edit execution-mitigation flags in writable ELF files; source behavior is
unchanged. Qualification edits only disposable copies and verifies exact note
changes. Existing filesystem/signature policy must still govern permitted edits;
this migration establishes neither authorization enforcement nor audit coverage
for executable-policy changes. Record that operation for future system audit
review; do not infer it from successful file-write tests.

### factor and primes (2026-10-27)

Focused source inspection found no direct DTrace/SDT or audit submission hooks.
primes retains its maintained capability-mode entry; all four native maintained
behaviors execute it. factor retains optional OpenSSL number operations. These
unprivileged numeric utilities add no authorization decision in this migration.
Large-number/entropy paths and general syscall audit coverage remain unqualified.

### libcapability (2026-10-27)

The library source contains no direct DTrace/SDT or audit submission hooks.
It crosses meaningful kernel boundaries through capability ioctls, confinement
calls and coalition operations. Native migration retains these calls and source
ABI headers. Eight passing host executions validate four userland/error-path
cases in static/shared variants; three maintained live service cases remain
unrun. Verify tracing and authorization audit at the mac_capability/module and
service boundaries during matching-kernel qualification; library argument tests
do not establish that coverage. No authorization or probe behavior was changed.

### libchannel (2026-10-27; partial migration)

Preserves the maintained 15-probe provider for request/dispatch/handler lifecycle,
creation, queue/send/receive, completion/discard, peer death and pressure limits.
Traced native and Make DSOs contain all probe names and .SUNW_dof; untraced DSOs
do not contain that section. Live firing, argument correctness, static-consumer
provider retention and full DOF semantics remain unqualified. An unintended
extra anchor symbol was found by static-export comparison and removed.
Kernel channel authorization and descriptor transfer still need module/service
tracing and audit qualification; library-only build comparisons cannot establish
those protections. Matching-kernel functional and soak tests remain outstanding.

Channel follow-up: all three native static test executables retain the channel
provider name and DOF via provider-only alwayslink. The SDK-linked Make references
do not retain that provider. Record this as a known retention difference, not
complete tracing equivalence; live firing and registration remain unverified.
The complete 38-case native graph now builds, with no runtime executions claimed.

### libfidl initial graph (2026-10-27)

The native graph retains the maintained fidl_bsd provider and generates its header
before compiling runtime code with WITH_DTRACE. DTrace processes declared ordinary
and PIC objects, with provider-only alwayslink for native consumers. Static/shared
symbol comparisons pass against Make after normalizing internal path-hash aliases.
This does not establish live provider registration, probe argument accuracy,
service audit coverage or runtime behavior. These remain explicit qualification
obligations along with channel/kernel tracing.

FIDL follow-up: the maintained native wire-codec test passes 39,639 checks against
freshly generated bindings. This covers userland codec/descriptor behavior, not
live channel/module authorization, service auditing or DTrace firing. The live C
binding program builds but remains unrun pending a matching guest kernel.

### libcapreclaim (2026-10-27; candidate)

No direct DTrace/SDT provider or audit submission hooks were found in this
library. Its callbacks enumerate and destroy resources; authorization and
security-relevant destruction records must be reviewed in the service callers.
The 28 maintained cases exercise owner/grace reconciliation and failure paths
with test callbacks; static/shared passing results do not demonstrate real
resource destruction auditing or service-level probe coverage. Native migration
preserves the existing implementation without introducing observability hooks.

### libucl (2026-10-27; candidate)

No direct DTrace/SDT or audit submission hooks were found in the imported C
implementation. UCL parses and emits data; security policy decisions and records
belong to its callers. Review configuration acceptance/rejection, reload and
policy-change auditing in Capsule/Switchboard as they migrate. This native build
preserves the imported sources and does not claim service audit coverage.

### libcapsulert (2026-10-27; candidate)

Preserves capsuleclaims:rights-parsed instrumentation for jail, file and storage
rights parsing through the maintained diagnostics provider. The traced shared
library contains DOF and the untraced library does not; static/shared symbols
match Make with DTrace path-hash normalization. Live firing and argument values
remain unverified. No direct audit submission was found in the three library
sources. Review successful/failed policy application and reload audit in service
callers; parsing/namespace tests do not establish authorization enforcement or
service-level audit coverage. Filesystem policy parsing has no dedicated test
program in the maintained libcapsulert test Makefile; record that coverage gap
for subsequent service qualification, without inventing a passing result.

### libcapimage (2026-10-27; candidate)

No direct DTrace/SDT or audit submission hooks were found in capimage.c. This
library verifies and signs executable policies, so service callers and the kernel
must be checked for verification failures, key/trust decisions and authority-grant
records. The migrated ELF/signature tests and syscall-wrapper test establish only
userland behavior. Seven live-kernel tests and root trust-directory qualification
remain unrun; no kernel integrity or audit coverage is claimed from these tests.

### libcapbundle (2026-10-27; candidate)

No direct DTrace/SDT or audit submission hooks were found in the four library
sources. The parser and signing/verification boundary requires caller-level audit
of trust decisions, rejected manifests, management-class changes and activation
policy. The 179 C tests cover parsing/validation/API behavior, not actual authority
grants or service audit records. Preserve and qualify the Capsule/Switchboard
records when their native targets become available. Shell-format tests remain
unrun until their matching switchboardctl dependency is native and declared.

### libtrustedzfs (2026-10-27; candidate)

No direct DTrace/SDT or audit submission hooks were found in trustedzfs.c. Calls
cross into ZFS handle ioctls for creation, destruction, snapshots, mount and other
operations; review kernel and caller audit/probe coverage at those boundaries.
The 13 descriptor tests preserve ioctl wrapping and test actual descriptor
restriction behavior but do not demonstrate a real ZFS-handle operation or its
audit trail. No host pool/dataset mutation was performed during qualification.

### libservice (2026-10-27; library candidate)

Carries forward four ambient-registration probes (create/send/ack/result) and six
runtime probes for retry, health, budget and lease pressure. Native rules process
both providers through the maintained service_ambient_provider.d. Symbol/archive
comparison passes against Make with only internal DTrace path-hash normalization;
live registration, firing and arguments remain unverified. Service authorization,
worker authority changes, discovery fallback and storage access must be checked
with Capsule/Switchboard runtime and audit behavior; building the library alone
does not establish those protections or their observability.

Service follow-up (2026-10-27): 11 runtime/bootstrap/deadline cases now pass with
the maintained test compilation/injection behavior. They do not exercise live
provider registration, kernel authority or service audit records. The real
switchboardctl helper now builds, but its management operations and authorization
paths have not been exercised; no audit-coverage claim follows from that build.

### libfilesystemcmp (2026-10-27; incomplete build candidate)

The library uses generated FIDL bindings and service calls; qualification must
include filesystem service/kernel audit of storage opens, policy rejection,
snapshots, rollback and transaction operations. Generated binding equality and
library symbols do not prove those operations or their audit coverage. No
standalone tests Makefile exists here; service API and live integration coverage
must be carried forward. Link ordering and installation remain unfinished.

Filesystem client follow-up (2026-10-27): dependency ordering and complete
installation comparisons now pass against Make. All nine generated bindings
match. Live filesystem operation and audit/probe qualification remain unchanged
and unverified; installation equality is not runtime evidence.

Service API follow-up (2026-10-27): API argument/descriptor rejection and identity
wire-layout cases pass natively. All 22 API/ambient/identity cases build; live
sender identity, discovery context, provider/session behavior and auditing remain
unrun. Root/exclusive requirements and cleanup are represented, but exact ATF
case-timeout enforcement remains an adapter gap before live qualification.

### 2026-10-27 ATF deadlines

Service API declarations now carry maintained explicit timeout values; native
runner deadlines preserve cleanup after a timed-out body. Lifecycle 17/17 and
two actually executed API host cases passed; see README and
bazel-atf-phase-timeouts-20261027. Live service/kernel cases remain unexecuted.
Remaining gaps: other suites' timeout metadata, outer cancellation cleanup,
detached descendants and remaining ATF metadata semantics. No probe coverage or
full-runtime qualification is inferred from these harness checks.

### 2026-10-27 libservice installed test payload

Native installation now preserves all maintained libservice tests/helpers,
Capsule harness, exclusive Kyua metadata and ten provider source fixtures.
All 107 installation records and eight program ELF linkage contracts match the
independent Make reference (bazel-libservice-full-install-r2-20261027). Provider
source exports serve the installed worker-authority contract check; they are not
native daemon build targets. The shell suite and guardian were not executed.
Runtime authority/cleanup and live DTrace observations remain unqualified; the
existing library provider implementation was not changed in this step.

### 2026-10-27 libservice source dependency observation

A reversible service_client.c comment edit caused exactly the two library
compilations and the source-including client_deadline_test compilation. Identical
object outputs allowed downstream DTrace/link/install/test reuse. The unchanged
repeat ran no actions; baseline executed 11 host cases and reused two API cases.
All 13 passed outcomes were accounted for, with cached results distinguished.
See bazel-libservice-incremental-audit-20261027/verified.json. This is build graph
observability, not evidence of live DTrace probes or managed service operation.

### 2026-10-27 Switchboard native build

The native daemon preserves USE_BSM_AUDIT and switchboard_audit.c, its libbsm
dependency, and the maintained provider with 76 declared probes. Traced/untraced
binary comparisons match Make symbols and ELF linkage; DOF is present only in
the traced daemon. Probe declaration count is not evidence that every probe has
a compiled callsite or fires at runtime. Full DOF and live audit/probe checks
remain open, alongside the daemon's test migration and managed-service runtime.

The switchboard-nss helper has no own DTrace provider or direct libbsm dependency
in either Make or Bazel. Review the launcher's audit coverage when qualifying NSS
success/failure and authority stripping; do not infer that helper operations are
individually audited. The native migration did not add or remove instrumentation.
See the bazel-switchboard-{native-r2,install,notrace}-20261027 evidence directories.

### 2026-10-27 Switchboard logic and NSS tests

36 cases across seven maintained programs pass through native Bazel adapters.
NSS child setup/failure tests preserve their injected syscall/exec checks; these
exercise call ordering and fail-closed control flow, not kernel enforcement.
Real NSS helper framing and account round trips now use the declared native
helper under ordinary credentials. Manifest comparison, calendar selection,
bundle selection and rc ingestion are covered without launching Switchboard.
Audit emission, live DTrace and protected NSS-launch tests remain open. Evidence:
bazel-switchboard-tests-r2-20261027/qualification/host-results.json.

### 2026-10-27 Switchboard policy cases

18 additional host cases passed: pure lookup/launch/storage-recipient decisions,
container identity/fresh-directory behavior, restart names, descriptor limit
raising and injected OOM-policy failures. Two descriptor-reserve cases terminate
with SIGSYS using either Make or Bazel builds and identical source-SDK libraries;
source/host descriptor syscall numbers differ. Keep these live policy cases
pending a matching kernel; do not infer reserve/shedding coverage from the pure
limit tests. Four other credential/Capsicum cases remain unexecuted. No new live
DTrace or audit-emission evidence. See the policy-tests and fd-budget-host-abi
qualification directories recorded in README.

### 2026-10-27 Switchboard management and registry behavior

66 additional cases ran and passed: management/control decisions, rc selection,
responsible-parent decisions with injected coalition operations, real kqueue
registry watch/retry/coalescing behavior on temporary roots, and bounded policy
parsing. Native shared implementation targets compile the five common management/
NSS units once for two consumers; the action log confirms reuse. Runtime audit
records, active probes, coalition enforcement and real daemon startup remain
separate qualification gates. Evidence: bazel-switchboard-management-tests-
20261027/qualification/host-results.json and binary-comparison.json.

### 2026-10-27 static provider retention regression — unresolved

Seven launch/cleanup cases pass, using real process descriptors/kqueue with
injected failure paths and syscall doubles for authority revocation. The binary
audit fails two of the four programs: cleanup_status retains 188,760 extra text
bytes; worker_cleanup retains 392,051. Provider-only alwayslink is not sufficient
to preserve archive dead-code selection: the forced provider's strong DOF
relocations root otherwise-unused instrumented functions and dependencies.

Do not count this batch as qualified. Revisit prior traced static consumers and
qualify selective retention together with live probes; dropping registration or
silencing the comparison is not a fix. No CPU/RSS performance claim is made from
ELF size alone. See bazel-switchboard-cleanup-tests-20261027/qualification/
link-retention-audit.json and the retained provider undefined-symbol evidence.

### 2026-10-27 per-member DOF prototype — garbage-collection gate failed

Ordinary archive selection retains only the selected code/DOF members in four
prototype consumers, including a plain member in a mixed library. The fifth,
--gc-sections case still retains instrumented code after its caller is discarded:
registration constructors remain roots. Do not promote this experiment as the
fix or count preserved DOF records as live-probe evidence. Current host lacks
DTrace helper/control devices. Investigate standard ELF section associations and
retain both the unused-member and dead-caller regressions. R4/r5 experiment
qualification receipts record the passes and the unresolved failure separately.


### 2026-10-27 static DTrace metadata liveness counterexample

The archive-member prototype is still not qualified. Single-section metadata
association works in an isolated link experiment, but a new two-function,
two-section native Bazel fixture exposes the general problem. Associating a
shared DOF/init/fini record to only one function either retains unrelated code
or drops observability for a surviving function. This is not fixed by ordinary
executable tests passing. Evidence:
/usr/obj/usr/src/bazel-dtrace-link-order-20261027/receipt.json and
/usr/obj/usr/src/bazel-dtrace-archive-experiment-r6-20261027/qualification/multiple-association.json.
Captured input/output hashes, commands, and verifier scripts are retained.
The association experiments use host links of copied objects; the unmodified
multi-section candidate was also built through build-bsd and executed. No live
probe firing was established. No production consumer selects this experiment.
Require section-correct metadata or final-selected-code generation before
adopting a static tracing retention fix. Current alwayslink consumers still
need requalification against the original static-code-retention regression.


### 2026-10-27 DTrace per-section generation, association still pending

The optional `-x linksection=index` now gives build tools separate metadata for
one executable input section. Sixteen bounded tests pass, including sequential
rewrites and invalid requests with no input mutation. Ten default-mode captured
experiment outputs remain byte-identical. See
/usr/obj/usr/src/bazel-dtrace-section-filter-check-20261027/{receipt.json,default-parity.json}.
This does not resolve static retention by itself. Section metadata/registration
association and live probes remain required; existing alwayslink consumers
remain unqualified against the retention regression. Shared probe symbols,
is-enabled sites, PIC/shared linking, and tool-startup cost need coverage before
production adoption. No existing production rule opts into this filter.


### 2026-10-27 section-associated static prototype passes native retention suite

The archive_members experiment now generates/associates metadata per discovered
code section and preserves provider boundaries through relocatable linking.
Ten Bazel tests verify retained function/DOF/init/fini symbols and ordinary
execution, including shared probe/is-enabled symbols and application constructors.
R5 evidence: /usr/obj/usr/src/bazel-dtrace-section-member-r5-20261027. Four
corrected constructor cases executed; six earlier passes were cached. The R4
failure exposed a fixture initializer optimized away before instrumentation;
its replacement requires observable runtime initialization. Twenty-three
standalone generation/collision checks also pass under
/usr/obj/usr/src/bazel-dtrace-member-collision-check-20261027.
Live registration and probe firing, PIC/shared, real-library retention and
resource measurements remain outstanding. Existing base-library alwayslink
consumers have NOT yet been switched or requalified. No live-probe or system
completion claim follows from this fixture suite.


### 2026-10-27 real-library candidate removes observed cleanup retention excess

The default-off experimental_dtrace_section_archives setting now lets the
normal libcapsulert/libchannel graph qualify section-associated objects.
The candidate passes 18 selected tests (15 executed, three cached) and strict
symbol/linkage comparison for all four Switchboard cleanup binaries. The prior
274/678 extra globals disappear; text falls to 1,081,579/821,564 bytes for
cleanup_status_test/worker_cleanup_test. Evidence:
/usr/obj/usr/src/bazel-switchboard-section-dtrace-20261027/qualification/.
This is code-size evidence, not measured runtime/build CPU, memory or I/O.
Four PIC shared-library load/unload tests also pass, alongside ten static tests,
in /usr/obj/usr/src/bazel-dtrace-pic-member-20261027. Live probes remain untested;
real shared-library DOF semantics, package/debug metadata, cache and resource
gates remain before the experimental setting can become a default.


### 2026-10-27 bounded transformation cost measured, broad performance open

Five alternating default/candidate trials on identical real libcapsulert and
libchannel compiler inputs show ~5--6 ms additional CPU per three-object
transformation (~8--9%), similar per-command peak RSS, more write operations,
and larger logical intermediate outputs. Candidate output hashes repeat across
fresh roots. Corrected evidence:
/usr/obj/usr/src/bazel-dtrace-action-resources-r2-20261027/receipt.json.
The original run is explicitly invalidated because Python's inherited heap
contaminated RSS. A small native supervisor now measures children, with preserved
success/failure/signal/collision checks. Immediate ZFS allocation readings lagged;
a later allocation-snapshot.json records actual observed allocation separately.
No full Make-vs-Bazel, runtime, cold-cache or aggregate parallel memory claim is
made. Live probes and larger function-section-heavy inputs remain required.


### 2026-10-27 emitted and installed probe-site coverage verified offline

Candidate library installation metadata/debug links match Make (40 libcapsulert
records and eight libchannel library-only records). Static/shared symbol and
shared dependency comparisons pass; static archive layout intentionally combines
provider metadata with its code members. Emitted provider schemas, argument
mappings and function-relative offsets match Make for three libcapsulert sites
and 24 libchannel sites (19 channel probe records). Offline DOF relocation and
amd64 instruction checks validate every site against function bounds and patched
instruction bytes. The same checks pass after debug splitting/stripping using
CRC-bound separate debug files. Six static/PIC fixtures also validate is-enabled
sites. Evidence: bazel-section-dtrace-install-20261027/qualification and
bazel-dtrace-pic-member-20261027/qualification/enabled-site-checks.json under
/usr/obj/usr/src. This is stronger than section-presence evidence, but still
not live registration or probe firing. Runtime kernel/VM qualification remains.


### 2026-10-27 staged client and semantic invalidation evidence

Ordinary static/shared clients now link and run against extracted candidate
installation payloads. Static links retain correctly patched metadata without
Bazel-specific whole-archive forcing; 41 ordinary/15 enabled sites include SDK
libc providers and pass offline validation. Shared loader selection is verified;
unused target archives contribute no provider metadata. This remains parser/API
validation, not live channel IPC or DTrace firing. Evidence:
/usr/obj/usr/src/bazel-staged-capability-client-r2-20261027.
The unchanged installation repeat executes zero actions and reproduces ten
outputs. A fixture provider int->long edit triggers generation/compile/link
invalidation and changes emitted metadata; restoring exact source bytes/mtime
reproduces original artifacts. Both changed/restored phases pass 14 tests
(11 executed, three cached). Evidence:
/usr/obj/usr/src/bazel-dtrace-provider-invalidation-20261027.
Local cache/fixture checks do not qualify remote execution or the full system.


### 2026-10-27 libcapsulert installed test linkage correction

Independent pkg comparison exposed static Bazel test binaries versus shared Make
test binaries. The native tests now use declared capsulert/ATF shared dependencies;
eleven shared-runtime ATF cases pass. Library provider metadata remains in the
shared library; this change does not establish live DTrace registration/firing.
Evidence: bazel-capsulert-test-packages-r3-20261027 under /usr/obj/usr/src.
Prior static test/install evidence must not be used to claim shared install parity.


### 2026-10-27 libchannel packaged tests

Native test packages preserve Make's static channel_test/call_bench/ipc_soak
link policy and allocation wrappers. Separate debug CRCs and installed shell/
Kyuafile bytes pass offline comparison. This does not establish live channel IPC,
soak performance or DTrace firing; matching-kernel VM execution remains required.
Evidence: /usr/obj/usr/src/bazel-channel-tests-make-packages-20261027.


### 2026-10-27 Switchboard activation test review

activation.c already includes switchboard_audit.h/switchboard_probes.h and emits
AUE_SWITCHBOARD_ONDEMAND. The new native test keeps its maintained fixture behavior;
no new production probe or audit omission is established by this migration.
DTrace metadata presence matches the Make test, but live firing and audit-record
emission are not covered by these ten activation tests. Evidence:
/usr/obj/usr/src/bazel-switchboard-activation-20261027.


### 2026-10-27 NSS exchange observability review

nss_exchange.c and nss_child.c have no direct DTrace/audit calls. Review whether
existing caller-level diagnostics sufficiently expose helper launch refusal,
timeouts, malformed replies and descriptor cleanup before adding instrumentation;
this is an open observability review item, not proof of a missing security audit.
The native exchange test matches Make's lack of a DOF section. Its protected
process cases require matching-kernel execution and remain unqualified.
Evidence: /usr/obj/usr/src/bazel-switchboard-nss-exchange-r2-20261027.


### 2026-10-27 NSS isolation integration graph

The maintained isolation probe inspects executable-constructor state; it does not
claim to inspect every shared-library constructor. Native linkage matches Make,
and no instrumentation was removed. Four declared integration cases require a
matching kernel; two also need nonempty supervisor authority/discovery inputs.
None ran in this qualification. Keep the earlier NSS caller-level diagnostics
review open. Evidence: bazel-switchboard-nss-integration-r2-20261027 under /usr/obj/usr/src.


### 2026-10-27 bundle registry review

bundle_registry.c retains SWITCHBOARD_PROBE_MANIFEST_REJECT and syslog diagnostics
for trust/parse rejection. Migration changes no production instrumentation. The
long-path basename bug was fixed in libcapbundle, with a maintained directory
fixture regression. Three unprivileged cases pass; five root cases and live probe
firing remain open. Evidence: bazel-switchboard-registry-r3-20261027.


### 2026-10-27 domain/anointment audit contract

The native anoint_test preserves USE_BSM_AUDIT and the maintained switchboard_audit
capture stub. Passing host cases include refusal/audit-count assertions; these
check call arguments/counts, not emitted kernel audit records. Domain/anointment
binary DOF presence matches Make (none); shared-library metadata and live provider
firing are separate concerns. Forty host cases pass; sixteen root/channel cases
and one descriptor-syscall ABI case remain open. Evidence:
/usr/obj/usr/src/bazel-switchboard-domain-r3-20261027.


### 2026-10-27 on-demand test migration

Native on-demand tests preserve the maintained supervisor/service-protocol fixture
and exclusive scheduling. Production source probe/audit headers remain declared;
no probe removal or new instrumentation was introduced. Matching Make's absence
of test-binary DOF does not establish live provider firing. Eighteen host cases
pass; five live root/channel cases remain open. Evidence:
/usr/obj/usr/src/bazel-switchboard-on-demand-r2-20261027.


### 2026-10-27 plain scope contracts

Scope identity/storage/CLI fixtures keep maintained assertions and production
source inclusion; ELF/DOF presence matches Make. These test parsing and scoped
storage identities, not live audit emission or probe firing. No instrumentation
was removed. Evidence: /usr/obj/usr/src/bazel-switchboard-scope-contract-r2-20261027.


### 2026-10-27 scope runtime fixture

Native scope_runtime_test retains maintained management/runtime implementation
inclusion and static-library DOF presence matching Make. Its assertions do not
establish live broker events, kernel audit records or probe firing. No production
instrumentation was removed. Evidence: bazel-switchboard-scope-runtime-20261027.


### 2026-10-27 scope registry fixture

Maintained scope registry assertions and real parsed bundles pass with captured
libraries. The fixture intentionally supplies authenticated owner UIDs and bypasses
filesystem-owner scanning; it does not qualify that trust boundary or live probes.
Native binary metadata matches Make. Bazel test integration remains pending.
Evidence: /usr/obj/usr/src/bazel-switchboard-scope-registry-20261027.

### 2026-10-27 scope registry Bazel execution

The unchanged scope_registry_test now passes as a native Bazel test, using explicit
runtime library runfiles and a static exec adapter. No test output normalization
or registry assertions were removed. The runner preserves stderr and failing exit
status/signals, checked separately against the captured binary. Evidence:
/usr/obj/usr/src/bazel-switchboard-scope-registry-run-20261027.
This is fixture-level registry behavior, not live broker authorization, audit
emission, kernel operation or DTrace firing. No new production probe requirement
is inferred from the test runner.

### 2026-10-27 verified-handle consumer

Native verified_handle_consumer_test passes unchanged with syscall wrappers and
CAPIMAGE_EXPERIMENTAL_CONSUMER confined to the fixture. It does not fire DTrace
probes or demonstrate kernel audit emission. The compiled authority.c, capimage.c
and libcapbundle_sign.c contain no direct audit/probe calls found in this review;
review caller-level rejection diagnostics when qualifying the live broker, rather
than inferring missing instrumentation from this mocked consumer test alone.
Bazel and recorded Make ELF both lack a DOF section. Evidence:
/usr/obj/usr/src/bazel-switchboard-verified-consumer-20261027/qualification.

### 2026-10-27 Switchboard integration helper builds

capd_test_guardian, capd_service_fixture, capd_protocol_fixture and service_probe
now have native Switchboard targets. All match recorded Make ELF/symbol structure;
none has a DOF section in either build. These are test helpers, including deliberate
malformed protocol inputs and ambient-channel reachability checks. Their successful
compilation does not establish live probe/audit coverage or daemon reachability.
Preserve explicit missing-channel/skip outcomes when wiring the shell suites;
do not report them as successful service operation. Evidence:
/usr/obj/usr/src/bazel-switchboard-fixtures-r2-20261027/qualification.

### 2026-10-27 Switchboard shell payloads

The staged anoint_observability_test carries the configured DTrace setting and
matches Make bytes with DTrace enabled. This verifies generation only; neither
its source-contract assertions nor dtrace parsing/firing were executed. Nine shell
programs and four support files have byte/metadata parity evidence under
/usr/obj/usr/src/bazel-switchboard-shell-files-r2-20261027/qualification.
Source fixture staging and explicit runtime tool dependencies remain required.

### 2026-10-27 bundle shell tool selection

The maintained bundle integration script now invokes an explicitly configured
control executable by its quoted path. This prevents PATH fallback from testing a
different binary. Existing test assertions and probe/audit expectations remain;
only executable selection changed. Selection checks source the script with ATF
stubs and do not execute bodies or establish live observability coverage.
Evidence: bazel-switchboard-shell-files-r3-20261027/qualification under /usr/obj/usr/src.

### 2026-10-27 Switchboard installed test index and debug payloads

The complete native Kyuafile preserves Make's test interfaces and eight exclusive
program declarations byte-for-byte. All 43 binary/debug pairs have matching debug
links and CRCs, preserving separate symbols for diagnosis. This does not establish
live DTrace firing, audit emission or installed runtime execution. The source
fixtures consumed by observability/manifest shell checks remain to be staged.
Evidence: /usr/obj/usr/src/bazel-switchboard-test-install-20261027/qualification.

### 2026-10-27 Switchboard source-contract fixtures

All 32 maintained source fixtures are now declared and staged, including
switchboard_provider.d, switchboard_probes.h, the anointment tracing script and
bsdinstruments capability profile. All bytes and file metadata match recorded
Make installation. The 19 staged UCL manifests also match the current complete
source-tree inventory. Tests consuming these fixtures still require execution;
no DTrace parsing/firing or live audit emission is claimed.
Evidence: /usr/obj/usr/src/bazel-switchboard-source-fixtures-20261027/qualification.

### 2026-10-27 complete Switchboard test archive

All source-contract fixtures and test binaries now coexist in one native test
archive with correct directories and the Make-equivalent Kyuafile. Forty-three
separate debug pairs validate after extraction. Archive qualification does not
execute the suite or establish DTrace/audit behavior. Evidence:
/usr/obj/usr/src/bazel-switchboard-test-archive-20261027/qualification/switchboard.

### 2026-10-27 manifest contract execution blocked before body

All four maintained manifest policy cases were attempted through native Bazel ATF.
Every case failed before its assertions because candidate dirname aborts during
Capsicum rights validation on this older host. Isolated reproduction and source/
installed mask differences are retained in bazel-switchboard-manifest-tests-20261027/
diagnosis under /usr/obj/usr/src. There are zero passing runtime cases in this
attempt. Matching-system execution and regular-file fixture staging remain pending;
no live management-gate/audit behavior follows from the case names or source greps.

### 2026-10-27 regular source-contract tree

Contract source fixtures now use a declared directory artifact containing regular
files, preserving installed find -type f semantics. All 32 fixture bytes match and
runfiles enumeration succeeds. This removes a representation discrepancy without
changing manifest expectations. No ATF body, audit emission or probe firing is
claimed; matching-system shell runtime remains pending. Evidence:
/usr/obj/usr/src/bazel-switchboard-manifest-tree-r2-20261027/qualification.

### 2026-10-27 Capsule native candidate

All maintained Capsule sources and the 58-declaration capsule DTrace provider are
carried into native Bazel. Compared with fresh Make: 82 function/probe schemas and
118 resolved sites match, including argument schemas/provider attributes. No live
firing is established. Source review found no direct BSM audit API calls in the
Capsule C sources searched; assess caller/kernel audit coverage for privileged
bootstrap, claim and control operations during live qualification before proposing
new instrumentation. Comments referring to an implementation audit are not BSM
emission. Build parity is not PID 1 or management-policy runtime evidence.
Evidence: /usr/obj/usr/src/bazel-capsule-r3-20261027/qualification.

### 2026-10-27 Capsule pure-helper test migration

Reviewed req_validate_test, capsule_lifecycle_test and capsule_plane_test: these
exercise header-defined validation/decision helpers and introduce no runtime
DTrace providers or direct audit emission. All 13 cases pass natively via Bazel.
This does not cover observability of the caller's actual PID1 transitions or
request handling; the daemon's existing DTrace site comparison remains separate.
No probe/audit instrumentation was removed during this test migration.

### 2026-10-27 Capsule release/ambient test review

system_release_test deliberately replaces CAPSULE_PROBE_DYN_RELEASE_SYSTEM with
a no-op in its maintained source and mocks release-system calls. The Bazel target
preserves that contract; its three passing cases do not prove probe firing or
kernel audit emission. capsule_ambient_test checks descriptor hygiene; only the
negative-descriptor case ran on this host. Successful pins need the matching
cap_clofork syscall ABI. No production probe was removed by this migration.

### 2026-10-27 config_test static DTrace discrepancy

Native Capsule config_test has capsuleclaims plus nameres/semwait provider metadata;
the maintained Make test reference has nameres/semwait only. Native/Make report
15/12 function-probe schemas respectively. Site decoding succeeds for both, but
schema parity fails. This is an open static-link/reference-provenance investigation;
do not disable probes or use matching symbol counts as proof of DTrace parity.
Inventories retained in bazel-capsule-config-20261027/qualification under /usr/obj/usr/src.

### 2026-10-27 config_test discrepancy cause confirmed

Linker extraction tracing proves normal Make linkage omits libcapsulert.a's
separate diagnostics_provider.o while extracting instrumented claim_parse.o.
A diagnostic relink retaining the original provider matches native provider
attributes and all 15 function/probe schemas, with valid decoded sites. The
native opt-in section-associated archive therefore retains metadata absent from
this normal Make reference. This diagnoses the earlier gap; it does not establish
live firing or fix Make's general static-provider retention. Preserve this as a
Make observability issue for follow-up; do not remove native probes for equality.
Evidence: bazel-capsule-config-20261027/qualification/link-diagnosis under /usr/obj/usr/src.

### 2026-10-27 libutil opt-in static-provider correction

libutil now has the same opt-in section-associated archive mode used by other
candidate libraries. Its native DTrace generator uses an explicit uninstrumented
bootstrap configuration to avoid a generator/libproc/libutil dependency cycle.
Target instrumentation remains requested. In the two Capsule storage/import
binaries, unrelated login/account code is no longer pulled by a whole-provider
reference. Both host cases pass, but crypto and other symbol differences remain.
Live logincap probe firing and broader libutil regressions remain unqualified.

### 2026-10-27 libutil shared-provider regression check

The opt-in section-associated libutil shared library matches fresh Make's logincap
provider attributes and one function/probe schema including arguments/site counts.
Both binaries pass amd64 site decoding; all 124 dynamic exports match. This closes
the shared metadata comparison for this configuration, not live registration/firing
or general runtime coverage. Evidence: bazel-libutil-bootstrap-20261027/qualification
under /usr/obj/usr/src. Repeated identical build reuses all actions and captures
identical artifacts; no performance claim follows from that cache check alone.

### 2026-10-27 Capsule test payload helpers

The installed capd_test_guardian and capd_bootstrap_fixture are maintained test
doubles; their native builds match Make's exported symbols/linkage and no DOF.
They are not production daemon observability coverage. Packaging the existing
shell tests and VM launch scripts does not demonstrate probe firing, audit events,
PID1 operation or successful boot; those executions remain pending.

### 2026-10-27 libstats userland migration

libstats compiles shared subr_stats.c/tcp_stats.c in userland mode. Source review
found no maintained userland DTrace provider or audit hooks to carry forward;
SI_SUB_KDTRACE is a kernel initialization ordering constant, not a probe. Both
Make/native shared outputs lack DOF and match exported symbols. Statistics library
operations are not by themselves an identified authentication/audit boundary;
no missing audit hook is asserted from this review. Kernel-mode builds and
observability/performance behavior remain unqualified. Evidence:
/usr/obj/usr/src/bazel-stats-install-20261027/qualification/stats.

### 2026-10-27 libipsec migration

The maintained library compiles policy conversion/error reporting plus generated
lexer/parser code, with no DTrace provider in its Makefile. Make/native shared
outputs both lack DOF. This userland policy parser is not proof of auditing at
kernel IPsec policy installation; that boundary remains a separate review/runtime
gate. No probe or audit coverage was added or claimed. Evidence:
/usr/obj/usr/src/bazel-ipsec-20261027/qualification/ipsec.

### 2026-10-27 nc migration

Maintained nc Makefile has no provider generation and both Make/native binaries
lack DOF in STATS enabled/disabled builds. The STATS option carries forward
statistics reporting; it is not DTrace or audit-event coverage. Generic network
connections should be reviewed at existing socket/kernel audit boundaries rather
than inventing utility audit hooks during build migration. No network runtime or
live observability qualification is claimed. Evidence: bazel-nc-r2-20261027 and
bazel-nc-nostats-20261027 qualification directories under /usr/obj/usr/src.

### Capsule logic runner follow-up (2026-10-27)

The 13 existing request/lifecycle/plane logic cases now execute through Kyua;
all passed with declared ATF/libc/libsys loader identities. They test pure
helpers and do not establish daemon audit events or DTrace probe firing.
No production probes were changed. Evidence:
/usr/obj/usr/src/bazel-capsule-logic-kyua-r3-20261027.

### Capsule release runner follow-up (2026-10-27)

Three mocked system-release cases and one negative-fd case passed through Kyua.
The existing system_release_test replacement of CAPSULE_PROBE_DYN_RELEASE_SYSTEM
remains a no-op, so these passes establish release-decision behavior, not live
DTrace or audit-event delivery. Successful ambient pinning awaits a matching
kernel. Evidence: /usr/obj/usr/src/bazel-capsule-release-kyua-20261027.

### cksum / sum (2026-10-27)

Native Bazel migration preserves checksumtool:file-start and file-done, selected
by the maintained DTrace option. Verified schema/argument maps and two ordinary
plus two enabled patched sites against fresh Make output. Untraced build has no
DOF. Evidence: bazel-cksum-20261027/qualification/dof-*.json under /usr/obj/usr/src.
No probes were dropped or introduced; live registration/firing remains untested.
This read-only checksum utility has no audit event integration added here.

### getaddrinfo (2026-10-27)

Reviewed maintained source/Makefile during migration: no utility-specific DTrace
provider or audit emission exists to carry forward. Numeric-address Bazel tests
exercise formatting/resolution without DNS traffic. Resolver-library probes and
NSS/DNS observability are not established by those tests; assess them with the
resolver integration suite rather than inferring coverage from utility success.
Evidence: /usr/obj/usr/src/bazel-getaddrinfo-tests-20261027.

### POSIX shared-memory / message-queue control utilities (2026-10-27)

Reviewed posixshmcontrol and posixmqcontrol source and Make definitions: neither
has a utility-specific DTrace provider or audit emission. No probes were lost in
Bazel migration; linked Make/Bazel binaries both lack DOF. IPC creation/removal,
permission changes and jail-scoped operations merit kernel audit/probe coverage
review during matching-kernel lifecycle qualification. Current eight CLI checks
establish only argument handling, not those events or isolation semantics.
Evidence: /usr/obj/usr/src/bazel-posix-controls-20261027/qualification.

### ministat, number, lsvfs (2026-10-27)

Source/Make review found no utility-specific DTrace provider or audit emission in
these commands. Both Make and Bazel linked binaries lack DOF. No probes were
removed. ministat retains caph_limit_stdio, input rights limits and caph_enter;
its runtime could not execute with the older host libc. Matching-system tests
must exercise those transitions without disabling the protections. number's
formatting checks passed; lsvfs kernel enumeration remains unqualified.
Evidence: /usr/obj/usr/src/bazel-small-utilities-r2-20261027/qualification.

### tty, logname, users (2026-10-27)

No utility-specific DTrace provider or audit emission appears in the maintained
sources/Makefiles. Bazel preserves the existing behavior and Capsicum calls;
linked Make/Bazel outputs have no DOF. tty terminal/status tests do not establish
login/PAM/session audit coverage. logname/users need session-level tests with
matching userspace and kernel, including utmpx reads under capability mode.
Evidence: bazel-login-utilities-20261027 and bazel-tty-tests-20261027 under
/usr/obj/usr/src.

### look and mkstr (2026-10-27)

No utility-specific DTrace provider or audit emission exists in the reviewed
source/Make definitions. Both Make/Bazel linked outputs lack DOF. look retains
input rights restrictions, catalog caching and capability entry; those paths
still need matching-system runtime checks. mkstr private-file transformation
comparisons establish output behavior only, not audit-event delivery.
Evidence: /usr/obj/usr/src/bazel-look-mkstr-20261027/qualification.

### mkdep and pagesize scripts (2026-10-27)

Both are installed byte-for-byte from maintained scripts, with no embedded
DTrace/audit instrumentation to migrate. Their compiler, shell and sysctl calls
retain existing observability; runtime comparisons do not qualify audit/probe
emission from those dependencies. No instrumented implementation was replaced.
Evidence: /usr/obj/usr/src/bazel-base-scripts-r2-20261027/qualification.

### which and perror (2026-10-27)

No utility-specific DTrace/audit instrumentation appears in maintained sources
or Make definitions; linked Make/Bazel outputs both lack DOF. perror's catalog
caching, standard-I/O limits and capability entry remain intact and await runtime
qualification. which private-path comparisons establish lookup semantics only,
not exec or audit-event behavior; no discovered command is executed.
Evidence: /usr/obj/usr/src/bazel-which-perror-20261027/qualification.

### locale (2026-10-27)

No utility-specific DTrace provider or audit emission exists in the reviewed
source/Make definitions. Matching Make/Bazel ELF outputs lack DOF; no probes were
removed. Nine POSIX C-locale output/error checks passed, but filesystem-backed
locale enumeration, non-C catalog access and resolver/library observability are
not established by those checks. Installed ATF payload was preserved exactly.
Evidence: /usr/obj/usr/src/bazel-locale-r2-20261027.

### ts timestamp utility (2026-10-27)

Reviewed maintained source/Make: no utility-specific DTrace provider or audit
emission to migrate. Linked Make/Bazel binaries lack DOF. Native tests retain
clock_gettime/localtime calls but use literal output formatting; they do not
qualify clock behavior, timing accuracy or syscall tracing coverage.
Evidence: /usr/obj/usr/src/bazel-ts-tests-20261027.

### backlight and ktrdump (2026-10-27)

Neither utility adds its own DTrace provider or audit calls in the maintained
source/Make definitions; matching binaries lack DOF. ktrdump consumes kernel KTR
records, so absence of userland DOF must not be interpreted as absence of tracing
functionality. Kernel record decoding and live/dump coverage remain untested.
Backlight ioctl and Capsicum behavior are retained but device/audit observability
needs separate runtime qualification. No host tracing/device settings changed.
Evidence: /usr/obj/usr/src/bazel-device-diagnostics-20261027/qualification.

### libmt and mt (2026-10-27)

Reviewed maintained source/Make definitions: no dedicated DTrace provider or
audit emission to migrate; Make/Bazel library and utility outputs lack DOF.
Native XML parser test establishes data handling only. Tape ioctl operations,
permission failures and audit/kernel probe delivery remain unqualified and
require isolated device fixtures; no host tape operation was attempted.
Evidence: bazel-mt-20261027 and bazel-mt-status-20261027 under /usr/obj/usr/src.

### fstat / fuser (2026-10-27)

No utility-specific DTrace provider or audit emission was found in the maintained
source/Make definitions; matching linked outputs lack DOF. This does not establish
observability of procstat queries or fuser signal delivery. Those kernel-backed
paths, jail visibility and permission failures require isolated runtime tests.
Current invalid-option checks exit before inspection/signalling; production
source and behavior were not changed.
Evidence: /usr/obj/usr/src/bazel-fstat-20261027/qualification.

### from, logins, ruptime, rwho (2026-10-27)

Maintained sources/Makefiles have no dedicated DTrace provider or audit calls;
linked Make/Bazel binaries have no DOF. from/rwho retain their capability entry
and descriptor restrictions. Account/mailbox/spool access and permission failures
need isolated runtime fixtures; build parity does not establish NSS, audit or
kernel-probe coverage. No instrumentation was removed or added in this migration.
Evidence: /usr/obj/usr/src/bazel-account-status-20261027/qualification.

### USB HID library and utilities (2026-10-27)

No dedicated DTrace/audit instrumentation appears in the maintained HID library
and utility Make/source definitions; Make/Bazel linked outputs lack DOF.
usbhidaction uses syslog, which remains unchanged. Device access, configured
command execution and syslog/audit delivery need isolated runtime tests. The
pre-existing full-width report-field shift/bounds concern in libusbhid/data.c
also requires focused qualification; current evidence is build/install only.
Evidence: /usr/obj/usr/src/bazel-usbhid-20261027/qualification.

### HID field follow-up (2026-10-27)

The prior data.c bounds concern is reproduced and corrected in common source.
A guard-page test fails before the fix (139), then passes 5,120 field combinations
with the Bazel and Make libraries. No instrumentation changed. USB device access,
usbhidaction command execution and syslog/audit delivery remain unqualified.
Evidence: /usr/obj/usr/src/bazel-usbhid-fixed-20261027/qualification/libusbhid;
before/after test runs are recorded in README.md.

### last and ac (2026-10-27)

No dedicated DTrace providers, SDT probes, explicit audit submission or syslog
calls were found in these utility sources/Make definitions. Both Make and Bazel
outputs lack DOF. last retains caph_limit_stdio, timezone/catalog caching and
caph_enter via source Capsicum headers; host libc ABI prevents runtime validation.
ac's private-file smoke checks do not establish session accounting correctness.
Follow-up: nonempty synthetic login/logout/boot/clock-change records, libxo modes,
permission/error paths and kernel audit observation in a matching environment.
No instrumentation was removed. Evidence: bazel-account-history-20261027 and
bazel-account-history-tests-20261027 under /usr/obj/usr/src.

### lastcomm (2026-10-27)

No dedicated DTrace/SDT provider, explicit audit submission or syslog call found
in lastcomm/readrec sources or Make definition. Both linked variants lack DOF.
Six existing accounting-read TAP cases pass against Bazel and Make using private
fixtures; these check consumption of records, not kernel accounting generation
or audit event delivery. Follow-up: malformed/truncated record behavior, access
failures and matching-environment accounting/audit integration. No probes removed.
Evidence: /usr/obj/usr/src/bazel-lastcomm-20261027/qualification.

### lastcomm native TAP execution follow-up (2026-10-27)

The maintained six-assertion accounting TAP suite now passes through Bazel/Kyua
with lastcomm selected from a declared executable label. A name-collision test
proves candidate lookup ahead of host commands. This closes the native runner
gap, not the pending live accounting/audit or i386 execution gaps. Installed
payload is byte-identical to the prior qualified archive; no probes changed.
Evidence: /usr/obj/usr/src/bazel-lastcomm-kyua-adapter-20261027.

### getconf (2026-10-27)

Preserved configquery operation-start/operation-done, including enabled checks
and errno-preserving wrappers around trace_sysconf. Native and Make schemas and
function-relative sites match and both pass AMD64 patch validation; absolute
link addresses differ. Three maintained ATF cases pass through Bazel/Kyua.
The provider currently covers the sysconf wrapper; confstr/pathconf and errors
outside that wrapper need separate coverage review. No explicit audit submission
was added. Live probe firing and DTrace-disabled variant qualification remain
outstanding. Evidence: /usr/obj/usr/src/bazel-getconf-tests-r2-20261027/qualification.

### getconf DTrace-disabled follow-up (2026-10-27)

The native dtrace=false variant now matches Make WITHOUT_DTRACE: absent DOF,
fifteen defined globals, matching installation/debug metadata, and three passing
maintained ATF cases through Kyua. The earlier DTrace-disabled qualification gap
is closed. Live firing, confstr/pathconf instrumentation coverage and audit
integration remain unqualified. Evidence: bazel-getconf-nodtrace-20261027 under
/usr/obj/usr/src.

### getopt, proccontrol and protect (2026-10-27)

No dedicated DTrace/SDT providers, explicit audit submissions or syslog calls were
found in the maintained sources/Make definitions; Make/Bazel outputs have no DOF.
getopt retains caph_limit_stdio/caph_enter and source-header dependency, but host
libc blocks execution. proccontrol/protect validation-only checks do not cover
kernel procctl auditing, policy changes, inheritance, or group operations. Those
need isolated-child/matching-kernel coverage and audit observation. The preexisting
protect repeated-ID parsing issue is recorded in README.md. No instrumentation
was removed. Evidence: /usr/obj/usr/src/bazel-process-utilities-20261027/qualification.

### procstat and pargs/penv/pwdx aliases (2026-10-27)

Preserved processquery operation-start/operation-done around the traced process
lookup wrapper, with provider schema and AMD64 site parity against Make. No live
firing observed. Argument validation passes for all aliases, but actual queries,
libxo modes, credentials/files/kqueues, coalition/VM outputs, core files and
kernel-stack coverage remain unqualified. The installed ATF suite is retained;
matching-library/kernel execution and audit observation remain follow-up work.
No explicit userland audit submission added or probes removed. The signed VM
count warning is recorded in README.md.
Evidence: /usr/obj/usr/src/bazel-procstat-20261027/qualification.

### procstat configuration/type follow-up (2026-10-27)

DTrace-disabled and tests-disabled component variants now have fresh Make parity
evidence, respectively bazel-procstat-nodtrace-20261027 and
bazel-procstat-notests-20261027 under /usr/obj/usr/src. The common-source VM display
count/index type now matches its unsigned public API. Seven other count-type
diagnostics remain inventoried in README.md and the untraced qualification run.
Neither this type fix nor option parity establishes live DTrace firing, process
query behavior, audit events or execution of the installed ATF suite.

### procstat count-caller follow-up (2026-10-27)

Program process counts, sort helper and VM display now agree with unsigned
libprocstat count APIs. Fresh default Make/Bazel binary/install parity is retained
in bazel-procstat-counts-20261027 under /usr/obj/usr/src. Four library-side signed
count diagnostics remain; no public ABI change, pointer cast or warning suppression
was introduced. Live query/audit/ATF and post-correction live DTrace qualification
remain outstanding.

### dmesg, mknod and nfsiod (2026-10-27)

No dedicated DTrace/SDT providers or explicit audit submission found in these
sources/Make definitions; Make/Bazel linked outputs lack DOF. dmesg consumes
syslog-style kernel records but this migration does not verify record generation,
ring reads/clearing or timestamps. mknod needs isolated successful-node and failed
permission/audit coverage. nfsiod can load NFS before parsing options and therefore
was not executed on the host; module loading and NFS sysctl control need VM audit
qualification. No probes removed or extra service manifests introduced.
Evidence: /usr/obj/usr/src/bazel-sbin-utilities-20261027/qualification.

### accton and chkgrp (2026-10-27)

No dedicated DTrace/SDT providers, explicit audit submissions or syslog calls found
in these source/Make definitions; linked Make/Bazel outputs lack DOF. accton tests
stop before acct(), so enabling/disabling accounting and corresponding kernel
audit events remain VM qualification work. chkgrp private valid/malformed input
checks and two native Bazel cases pass; this is not exhaustive parser or audit
coverage. No probes removed or extra policy files introduced.
Evidence: bazel-account-admin-20261027 and bazel-account-admin-tests-20261027 under
/usr/obj/usr/src.

### libshmring initial native library (2026-10-27)

Preserved the shmring provider, including create/open/close, read/write,
consumer-arm/producer-wakeup, corrupt and record-reject probes. Shared-library
schemas and function-relative sites match Make; AMD64 patch checks pass. This is
metadata coverage only. Live firing, producer/consumer concurrency, rights and
corruption cases await native test/benchmark integration and matching runtime.
No probes removed and no extra audit events invented.
Evidence: /usr/obj/usr/src/bazel-shmring-20261027/qualification/libshmring.

### libshmring native runtime follow-up (2026-10-27)

All fifteen maintained ATF cases pass through Kyua in bazel-shmring-tests-20261027,
including concurrency, rights, corruption and wakeups; the static benchmark also
completes a bounded smoke run. These improve runtime coverage but do not establish
live DTrace firing or measured observer overhead. Existing provider preservation
checks remain scoped to the shared-library evidence above.

### libauditcmp initial native candidate (2026-10-27)

The library is itself the bsd.audit.v1 client and preserves its request bindings
and legacy record validation. No dedicated DTrace provider is declared by its
maintained Makefile. Byte-identical generated bindings and matching shared exports
do not establish audit delivery, peer identity attribution, rejection behavior or
provider persistence. Those require maintained client/lifecycle and service tests;
none were executed in this library-only turn. Static C++ symbol parity is pending.
Evidence: /usr/obj/usr/src/bazel-auditcmp-pic-20261027/qualification/libauditcmp.

libauditcmp follow-up: static-symbol mismatch resolved by preserving distinct Make
C and C++ static compilation semantics. Exact static/shared symbols now match in
bazel-auditcmp-staticflags-20261027. Audit delivery and lifecycle checks remain
pending; no observability coverage is implied by this compilation correction.

libauditcmp test follow-up: four maintained API/record validation cases pass through
Kyua in bazel-auditcmp-tests-r3-20261027. Both static test programs and full test
installation build, but seven root/matching-kernel lifecycle cases remain unrun.
No actual BSDAudit backend persistence, session attribution or service failure
coverage is claimed by these four checks.

### liblogcmp native library (2026-10-27)

Preserves logcmp provider: component open, message send/receive/reject, record
enqueue, wakeup send, ring attach, flush/query completion and reconnect. Native
and Make shared-library provider schemas, function-relative locations and AMD64
patch sites agree (twelve function/probe schema entries). Evidence is retained at
/usr/obj/usr/src/bazel-logcmp-20261027/qualification/liblogcmp. Live firing,
observer overhead, data delivery and service failure behavior remain unqualified;
no new audit events or service manifests were invented.

### liblogcmp test integration and host boundary (2026-10-27)

Native static test programs now build, retaining the maintained lifecycle wrapper,
fake provider and explicit generated bindings. Six API/record-validation cases
pass; wakeup is broken on the running host. Independent Make wakeup also dies
with SIGSYS. Retained truss output shows syscall 1000 returning ENOSYS after
cap_fcntls_limit; source syscall.h identifies it as cap_xfer_limit. No fallback,
skip or disabled test was added. The 26 root/matching-kernel lifecycle cases
remain unrun. No live logging, observer overhead or backend persistence is claimed.
Evidence: /usr/obj/usr/src/bazel-logcmp-tests-20261027, including failure-test-reports
and qualification/make-wakeup.

### BSDLog native executable candidate (2026-10-27)

The maintained bsdlog provider is declared through native header/object actions;
WITH_DTRACE remains configurable. Native/Make executables both contain DOF and
matching global definitions. Schema/site inventory and live service firing remain
unqualified; DOF presence alone does not establish correct operational coverage.
No provider events were removed and no policy fixture was invented.
Evidence: /usr/obj/usr/src/bazel-bsdlog-r5-20261027/qualification.

BSDLog follow-up: daemon_install qualification now compares full provider schemas
and function-relative locations, including all argument mappings and probe offsets.
Twenty-two function/probe entries and thirty-six ordinary AMD64 sites match Make;
ordering of location records is ignored, with full records retained. Both binaries
pass instruction patch checks. No live firing, persistence or performance claim.
Evidence: /usr/obj/usr/src/bazel-bsdlog-install-20261027/qualification/BSDLog.

BSDLog test follow-up: native configuration and session suites pass 8 and 9 cases.
Store suites total 3 passes and 43 broken cases on this host; a representative
Make case reproduces the missing cap_xfer_limit syscall. No storage persistence
qualification is claimed. Native C++ runtime symbol over-inclusion in three test
binaries remains under investigation. Tests preserve Make's direct untraced source
compilation; daemon DTrace qualification is separate.

BSDLog static-test follow-up: libc++ charconv alwayslink was unnecessarily pulling
static code; using explicit shared roots removes thirteen excess definitions and
retains 2050 shared exports with both libc++ runtime checks passing. Remaining
339 global differences include ABI definitions that Make keeps local, so the
previous description as entirely extra code was too broad. Static/shared ABI
archive modeling remains unresolved; no runtime kernel gate was relaxed.

BSDLog/libc++ follow-up: regular archive now embeds hidden ABI objects and shared
linkage uses separate PIC objects, fixing all remaining static test global-symbol
differences. Four static tests match Make exactly; config/session rerun passes
17 cases. Shared libc++ exports and BSDLog executable structure remain equal.
This does not change the missing-kernel-syscall gate or establish live DTrace.
Evidence: bazel-cxx-variants-r3-20261027 and bazel-cxx-downstream-20261027.

BSDLog storage test follow-up: native storage and barrier binaries have exact
Make global-symbol parity. The maintained deterministic ingestion-barrier case
passes, preserving all four fault-injection wrappers. Full storage-manager runtime
(22 cases), persisted backend behavior and live DTrace remain unqualified.
Evidence: /usr/obj/usr/src/bazel-bsdlog-storage-barrier-20261027.

BSDLog policy-test follow-up: native fallback/quota/fairness each pass their
maintained case; provider's six cases remain built-only. Exact static parity now
passes after fixing Make's fairness session.o flag collision with a distinct
wrapper object. No live provider audit/DTrace coverage is implied by these local
policy and fairness fixtures. Evidence: bazel-bsdlog-policy-tests-r2-20261027.

BSDLog evolution follow-up: explicit bsd:2 peer generation is byte-equal to Make,
and peer/harness static globals match. Both cross-version runtime pairings remain
unexecuted pending matching-kernel qualification. This does not establish live
provider compatibility or DTrace delivery. Evidence: bazel-bsdlog-evolution-r2-20261027;
generator comparison: bazel-bsdlog-evolution-20261027/qualification/generation-parity.json.

### BSDLog latency benchmark shared-link correction (2026-10-27)

Native latency_bench preserves shared libchannel for request USDT observations.
Make unexpectedly produced a static helper due to bsd.progs.mk override-list
membership handling. Corrected that handling and unset-default preservation;
a fresh Make build now matches native shared linkage (37 globals, six direct
project DSOs plus libc, PIE/BIND_NOW). Evidence is in
/usr/obj/usr/src/bazel-bsdlog-latency-20261027/qualification. The helper has no
own DOF by design; shared libchannel owns the request probes. Live firing and
latency distributions remain unmeasured on a matching kernel. No audit/probe
coverage is inferred from the successful link.

### BSDAudit native daemon (2026-10-27)

The native BSDAudit executable carries all four maintained provider probes:
request-done, session, submit and reject. Binary DOF comparison with fresh Make
passes ten function/probe schema entries, relative site records and AMD64 patch
checks. Evidence: /usr/obj/usr/src/bazel-bsdaudit-20261027/qualification.
This is preservation of emitted probes, not live firing or successful kernel audit
submission. No probe/audit integration omission was established by this build;
service runtime coverage remains outstanding.

### libservice multi-provider archive qualification gap (2026-10-27)

BSDAudit rate_test reveals 61 extra symbols from native static service linkage.
The aggregate DTrace provider retention contributes to extracting otherwise unused
service objects. The existing experimental per-member transformation cannot yet
handle libservice's combined service_ambient/service_runtime script when a member
has sites for only one provider: rate-r3 fails with "No probe sites found for
declared provider". The experiment was removed. Preserve both providers while
fixing extraction; do not suppress this error or disable instrumentation. Evidence:
/usr/obj/usr/src/bazel-bsdaudit-rate-20261027/qualification and
/usr/obj/usr/src/bazel-bsdaudit-rate-r3-20261027/bazel.stderr.

### Resolution of libservice multi-provider metadata failure (2026-10-27)

Explicit section linking now omits only providers absent from the selected code
section and still rejects an entirely empty result. Twenty-six filter regressions
pass. With experimental per-member mode, libservice preserves service_ambient and
service_runtime, all seven emitted function/probe schemas and relative sites,
verified against the retained Make shared library; AMD64 patch checks pass.
Its two DOF records replace the aggregate single record. Static BSDAudit rate
symbol parity is restored without disabling probes. Evidence: bazel-bsdaudit-rate-r4,
bazel-dtrace-multiprovider-check and bazel-service-multiprovider, all dated 20261027
under /usr/obj/usr/src. Live registration/firing remains outstanding.

### libfidl static extraction and shared probes (2026-10-27)

The retained aggregate FIDL provider forced unused runtime/C++ code into BSDAudit
shutdown/lifecycle tests. Existing experimental per-member mode now avoids that
retention and restores exact Make symbol parity. Shared libfidl retains all nineteen
function/probe schema entries, relative sites and 257 dynamic symbols versus the
Make reference; AMD64 patch checks pass. Evidence: bazel-fidl-downstream-20261027
under /usr/obj/usr/src. Seventeen host-safe downstream cases pass. Live tracing and
kernel-dependent audit-service cases remain unqualified.

### Time service dependency migration (2026-10-27)

libtimecmp native targets retain diagnostics_provider.d (wait-start, wait-done,
reply-malformed) and WITH_DTRACE selection. Static/shared symbol parity passes;
DOF schemas/sites and live probe firing are not yet qualified. BSDTime source has
request, clock-set and clock-adjust probes plus syslog notices for changes. Its
Make LIBADD and direct source inspection show no explicit libauditcmp integration;
review end-to-end time-change auditing through service/kernel paths before calling
that an audit gap or adding duplicate records. No instrumentation was removed.

libtimecmp follow-up: shared DOF comparison now passes against the fresh Make
reference: timecmp provider attributes, six function/probe schema entries,
relative sites and AMD64 patch validation; one DOF record in each library.
Evidence: /usr/obj/usr/src/bazel-libtimecmp-20261027/dof-qualification.
The six entries represent three probe names emitted at multiple function sites.
Live provider registration/firing remains untested.

BSDTime daemon follow-up (2026-10-27): native graph retains the existing request,
clock-set and clock-adjust provider. Fresh Make comparison passes six emitted
function/probe schemas, relative sites and AMD64 patch validation; one DOF record
in each executable. Evidence: bazel-bsdtime-r2-20261027/dof-qualification under
/usr/obj/usr/src. No live probe firing or clock-changing execution was performed.
The previously recorded end-to-end audit-path review remains open.

### BSDTimectl observability review (2026-10-27)

The operator CLI has no own DTrace provider or direct audit integration, matching
Make. It calls libtimecmp (wait/reply diagnostics), while BSDTime supplies request
and successful-clock-change probes and syslog notices. Review the complete audit
path at the service/kernel boundary; do not infer durable audit coverage from
client-library probes. No maintained component tests exist for this CLI. Retain
get/set/adjust, malformed inputs, signed deltas and denied-authority scenarios for
matching-kernel disposable-VM qualification. No clock operation was run during
native build/install comparison.

### libpowercmp observability review (2026-10-27)

The maintained library Makefile and sources declare no own DTrace provider;
the native graph preserves that behavior. Shared service/FIDL/channel dependencies
have their separately recorded instrumentation, which does not prove power-policy
or durable audit coverage. Review BSDPower's suspend/inhibitor operations and the
kernel gate audit path during daemon migration. Legacy protocol validation passes;
scripted-server client and constructor runtime still need the matching kernel.
No power-management command was executed.

### BSDPower daemon instrumentation (2026-10-27)

Native candidate preserves the existing request and suspend probes and source
syslog notices. Fresh Make comparison passes seven function/probe entries,
provider attributes, relative sites and AMD64 patches (one DOF record each).
Evidence: /usr/obj/usr/src/bazel-bsdpower-20261027/dof-qualification. Probe count
is emitted function/probe pairs, not distinct probe names. Live registration,
suspend behavior and durable audit integration remain open; source/Make inspection
shows no direct libauditcmp dependency. Review service and kernel audit paths before
adding records. No power-management operation was executed.

### BSDPowerctl observability review (2026-10-27)

The maintained operator CLI has no own USDT provider or direct audit-library call;
its native build preserves that. Real requests use powercmp/service dependencies
and BSDPower, whose probes are recorded separately. Duration tests exercise actual
CLI control flow with maintained simulated time/inhibitor hooks, not real power
policy enforcement or audit delivery. Keep denied authority, lease cleanup after
client death and permitted suspend/audit scenarios for disposable-VM qualification.

### libnotify native probe preservation (2026-10-27)

The native library preserves notify rpc/publish/next/reject/reconnect declarations.
Shared-library Make comparison passes all five emitted schemas, provider attributes,
relative sites and AMD64 patches. Evidence: bazel-libnotify-20261027/dof-qualification
under /usr/obj/usr/src. This does not establish live registration or notification
behavior. BSDNotify's explicit auditcmp/logcmp integration remains to be carried
forward when its daemon graph is implemented.

## BSDNotify native daemon review (2026-10-27)

The native daemon retains the maintained bsdnotify DTrace provider: eleven probe
schemas and relative sites match Make; AMD64 patch-site checks pass. Evidence:
/usr/obj/usr/src/bazel-bsdnotify-r2-20261027/dof-qualification. Live firing and
audit-event runtime coverage remain unqualified. Separate policy-embedding checks
now cover the daemon's unsigned CAPIMAGE_MANIFEST; this is not audit-delivery or
signature verification evidence.

### BSDNotify dispatcher/session migration follow-up (2026-10-27)

The native dispatcher suite runs the maintained embedded-router tests (23 pass).
The session and schema-evolution peer binaries match Make symbol inventories,
but their real channel runtime remains unrun on this older host. These results
do not establish end-to-end audit delivery or live DTrace firing. Preserve those
matching-kernel gates rather than treating dispatcher socket tests as substitutes.

## libsysctlcmp native migration review (2026-10-27)

The maintained library Makefile and sysctlcmp.c/sysctlcmp_legacy.c contain no own
DTrace provider or direct audit submission. Native migration has not added probes
or removed instrumentation. Review provider-side BSDSysctl authorization/audit
coverage and shared channel probes before claiming end-to-end observation of
sysctl reads/writes; the seven passing protocol/argument tests establish neither
live probe firing nor audit delivery. Real-channel client_strings runtime remains
pending on a matching kernel.

## BSDMemory daemon candidate (2026-10-27)

Retained bsdmemory provider and trace_pressure dependency-health probes. Eight
schemas/relative sites match Make and patch-site checks pass; live firing remains
unverified. BSDMemory source has no direct audit submission in the reviewed
paths. Review provider-side sysctl/notification audit behavior and whether
pressure-publication/dependency transitions need additional events; do not infer
coverage from the client's linkage alone. No new instrumentation was invented
as part of the build migration.

## BSDSysctl daemon candidate (2026-10-27)

Retained the bsdsysctl provider, including session open failure/limit/close-reason
instrumentation from trace_pressure.h. Nineteen schemas/sites match Make; live
firing is unqualified. The reviewed daemon source has no direct audit submission;
review underlying sysctl auditing and provider authorization-denial coverage
before claiming read/write audit completeness. Binary/DTrace metadata checks do
not establish that runtime chain. No additional probes were introduced during
migration.

### BSDSysctl static contract follow-up (2026-10-27)

The shell contract now passes against an explicitly supplied Bazel daemon and
declared source/profile fixtures. Evidence is bazel-bsdsysctl-observability-20261027.
This closes the fixed-host-path issue for the contract; live probes and end-to-end
audit delivery remain unverified. Host shell/grep/readelf are harness dependencies.

## libvmcmp native migration review (2026-10-27)

No own DTrace provider or direct audit submission appears in the maintained
libvmcmp Makefile/client source. BSDVM's provider probes and channel instrumentation
need review and live qualification as service tests migrate. The library lacks a
separate test subdirectory; build/install parity does not establish vsock endpoint
isolation, transport recovery or audit completeness. No instrumentation was added
or removed by this migration.

## BSDVM native daemon review (2026-10-27)

The native daemon preserves its optional bsdvm provider: five probe schemas,
provider attributes and relative sites match fresh Make, with valid AMD64 patch
sites (bazel-bsdvm-20261027/dof-qualification). Live firing is unqualified. The
source has request completion and vsock-list instrumentation but no direct audit
submission found in this review. Review the underlying transport/authorization
audit chain and runtime denial coverage when migrating service tests; binary
parity does not prove complete audit delivery. No probes were added or removed.

BSDVM follow-up: nine registry/validation cases now pass through native Bazel/Kyua
(bazel-bsdvm-tests-r3-20261027). Registry/provider test binaries match Make's static
symbol inventories; their VMD_TESTING build has no daemon DTrace definition, as
in Make. Provider runtime, live probes and end-to-end audit remain unqualified.

BSDVM's latency candidate now preserves Make's shared libchannel linkage and has
no own DOF, matching Make (bazel-bsdvm-remaining-r3-20261027). Lifecycle, serve and
evolution binaries also match static symbol inventories. No live probe firing,
latency, channel isolation or audit delivery is established by these build checks.

## libnetworkcmp native migration review (2026-10-27)

Preserved the existing networkcmp component-open and message-send/receive/reject
probes. Nine function/probe schemas, provider attributes and relative sites match
fresh Make in bazel-libnetworkcmp-20261027/dof-qualification; two native archive
member DOF records replace Make's one combined record. Live firing remains open.
The reviewed client has no direct audit submission; review BSDNetwork's existing
auditcmp calls and the transport/authorization chain before asserting end-to-end
network audit completeness. No instrumentation was added or removed.

libnetworkcmp follow-up: three maintained native test candidates now compile the
same client sources and link the same static libraries as Make. No tests or live
probes were executed in this step; runtime audit and channel behavior remain open.

## BSDNetwork native daemon review (2026-10-27)

Preserved the bsdnetwork provider: fifteen function/probe schemas, attributes and
relative sites match fresh Make, with valid AMD64 patches
(bazel-bsdnetwork-20261027/dof-qualification). Unlike the client library, the daemon
includes auditcmp and contains audit event construction/submission code. Build
parity does not prove delivery, denial coverage, lost-event handling or live probe
firing; qualify these with the real provider and audit service. No instrumentation
was added or removed by this migration.

BSDNetwork follow-up: fifteen config and seven policy cases pass using native
candidate libraries and the actual shipped policy fixture. This checks parser and
policy behavior, not end-to-end authorization, audit delivery or live DTrace.
Evidence: bazel-bsdnetwork-config-r2-20261027. No instrumentation changed.

BSDNetwork follow-up: resolver/recovery/provider test binaries now match Make's
symbol/linkage inventories (bazel-bsdnetwork-provider-r2-20261027). The static
provider retains linked-library DOF; no live probes or audit delivery were tested.
The tests compile maintained resolver/provider sources; no instrumentation changed.

BSDNetwork state/worker follow-up: two sampler, two coalescing and one deadline
case pass under native Bazel/Kyua using the maintained test mocks and real source.
No production instrumentation changed. These validate selected failure/shutdown
and deadline logic; live network/PF operations, probes and audit delivery remain
unqualified. Evidence: bazel-bsdnetwork-state-20261027 and
bazel-bsdnetwork-worker-unit-20261027.

BSDNetwork evolution/latency follow-up: the native benchmark retains shared
libchannel linkage and no own DOF, matching Make. Static evolution/peer symbol
inventories and nine generated files also match. Evidence is
bazel-bsdnetwork-evolution-20261027. No live channel probes, latency measurements
or audit delivery were exercised; no production instrumentation changed.

BSDNetwork worker/PF follow-up: static symbol inventories match Make for both
candidates (bazel-bsdnetwork-pf-worker-r2-20261027). They have not executed; live
probe/audit delivery remains open. PF's maintained fixture uses a stand-in fd and
real channels, so it does not qualify vnet-jail binding or actual firewall changes.
No instrumentation was added or removed.

## libtracecmp native migration review (2026-10-27)

Preserved existing open/send/receive/reject probes. Four schemas, attributes and
relative sites match Make; AMD64 patch sites validate with one DOF record each
(bazel-libtracecmp-20261027/dof-qualification). The reviewed client contains no
direct audit submission; review BSDTrace's policy/audit chain when migrating its
daemon/tests. Live tracing, device authority and audit delivery remain unqualified.
No instrumentation was added or removed.

libtracecmp test follow-up: four ABI/validation/API/tuning cases pass, but both
static test binaries fail global-symbol comparison with Make. C++ runtime and
libspl selection differences remain under investigation; these tests are not fully
qualified. No live tracing, device access or lifecycle execution was performed.
Evidence: bazel-libtracecmp-tests-20261027/qualification/binary-parity.json.

libtracecmp parity correction: explicit static runtime precedence plus DTrace
public/implementation header isolation now restores exact Make symbol inventories
for both tests (bazel-libtracecmp-tests-r4-20261027). Four host-safe cases pass.
SPL's assert.h no longer replaces the lifecycle fixture's system assert.h; no
assertion was removed or weakened. Lifecycle/live tracing remain unexecuted.

### DTrace consumer dependency follow-up (2026-10-27)

Public-header isolation uncovered a missing direct Solaris compatibility dependency
in plockstat; it is now declared. Retained public-consumers-r2 evidence builds both
DTrace library forms and both command consumers. dtrace still reports two handle
pointer-type warnings from compatibility-header precedence; correction and consumer
ABI/install regression checks remain open. No probes were removed, and no live
DTrace or audit behavior was exercised.

### DTrace compatibility wrapper correction (2026-10-27)

The preceding pointer warnings are corrected using the existing Solaris libproc
wrapper as a declared native header dependency for dtrace/plockstat. The r3 consumer
rebuild is clean for these commands and matches fresh Make symbol/linkage evidence.
This does not establish live probe behavior or full library ABI/install regression.
libtracecmp full installation now matches thirty-two records and retains both tests;
four host-safe cases pass, while real-channel lifecycle testing remains open.

### DTrace library structural regression (2026-10-27)

After header isolation, fresh Make comparison matches library static/shared symbols
and shared linkage. The complete directory-aware installation check found and fixed
two omitted directory ownership records; all twenty-five records now match. This
corrects the scope of the earlier twenty-three-entry claim. No live tracing or
new probe/audit coverage is established by installation or symbol equality.

### BSDTrace daemon review (2026-10-27)

Native compilation carries forward bsdtrace USDT instrumentation: session start/end,
delegation, rejection and request completion. Eight function/probe schemas and
relative patch locations match fresh Make. audit_policy still invokes audit_submit
with AUE_TRACECMP_POLICY; libbsm is an explicit dependency. No probe or audit source
was changed. This is source/binary structural evidence, not live probe firing or
successful audit-record delivery. Maintained policy/session/shutdown/lifecycle/
bootstrap/quota/evolution tests and runtime qualification remain to migrate.

### BSDTrace policy/session tests (2026-10-27)

Eleven maintained policy cases pass through the native candidate runtime. The real
per-session daemon test now builds with matching Make static symbols after correcting
C++ runtime precedence. It was not executed on the older host: real channels and
one-shot descriptor semantics remain matching-kernel gates. These tests do not prove
live DTrace access, audit delivery or probe firing; no new instrumentation was added.

### BSDTrace lifecycle test runtime limitation (2026-10-27)

Quota and three shutdown cases passed in the initial native run. One shutdown case
and lifecycle failed with empty results. Both Make/Bazel direct reproductions die
with SIGSYS; a retained Make lifecycle syscall trace identifies cap_process (1011)
returning ENOSYS during logging. No logging stubs or source fallback were added to
obtain passes. Corrected native builds match Make's static symbols, while runtime
qualification remains open on a matching kernel. Bootstrap remains unexecuted.

### BSDTrace evolution/benchmark build coverage (2026-10-27)

The maintained latency benchmark is now a native build candidate with shared
libchannel, matching Make. It exercises the real per-session client/server when run,
but uses the source's /dev/null stand-in for a DTrace consumer. No actual DTrace
consumer authorization, live probe observation or performance result follows from
its successful build. Evolution is compiled with separate bsd:2 peer bindings;
real-channel schema negotiation remains an unexecuted runtime gate.

### BSDTrace installed observability contract (2026-10-27)

The complete native test archive now carries the unchanged shell observability,
security and bounded-worker contract checks, plus all six maintained source fixtures.
Bytes and metadata match Make. The shell contract was not executed, and source grep
checks alone do not prove live probe firing, audit delivery or enforced isolation.
Existing host syscall/runtime failures remain open matching-kernel qualification.

### BSDTrace instrumentation-disabled variant (2026-10-27)

The native daemon has no DOF when dtrace=false, matching fresh component Make output;
service policy and full installed inventory remain intact. Twelve policy/quota cases
are reported passing from two cached suites, not newly executed. Functional libdtrace
API linkage remains intentional. No live audit/tracing or full-world option behavior
was qualified by this component comparison.

### libtracecmp instrumentation-disabled variant (2026-10-27)

Native/Make client libraries both omit DOF with optional instrumentation disabled,
while keeping required libdtrace API linkage. Generated bindings, symbols, shared
linkage and full installation compare equal. Four host-safe cases passed freshly;
real-channel lifecycle and live tracing/audit qualification remain unexecuted.

### libcryptocmp source observability review (2026-10-27)

The current client has no dedicated DTrace provider/probe calls or audit calls in
cryptocmp.c and no DTrace provider in its Makefile. Native migration preserves that
state; it does not add instrumentation silently. Review transport failure, terminal
client state and operation completion observability with the provider's existing
coverage. Any later crypto instrumentation must avoid keys, secret material and
payload disclosure. Provider-side audit delivery and operation authorization have
not been reviewed/qualified by this client build comparison.

### libcryptocmp API test coverage (2026-10-27)

Two existing argument-validation cases pass in the native build. The scripted-provider
protocol test compiles and matches Make's static symbols but is unexecuted because it
uses real capability channels. Neither result establishes provider audit delivery,
operation authorization, secret handling or live transport observability. No test
mocks or client instrumentation were changed by the migration.

### libcryptocmp installed tests (2026-10-27)

The full native archive now carries both maintained test binaries and protocol
root/timeout metadata, with exact Make installation comparison. Installing a protocol
test is not evidence of executed channel behavior or crypto-provider authorization;
those matching-kernel runtime gates remain open. No instrumentation changes occurred.

### libcryptodesc wrapper observability review (2026-10-27)

The current wrapper source/Makefile has no dedicated DTrace provider or audit calls;
native migration preserves that state. Two pre-ioctl argument-validation cases pass,
not real kernel descriptor operations. Review operation/error/revocation coverage
with kernel/provider instrumentation before adding client probes; avoid exposing key
material. Descriptor authorization, kernel audit delivery and live probes remain
unqualified by library build/install comparisons.

### libextensioncmp source observability review (2026-10-27)

The current client source/Makefile declares no dedicated DTrace provider or audit
calls. Native migration preserves that state. Review explicit/process-wide session
recovery, terminal transport failures and inherited-session rejection with provider
observability; no probes were silently added or removed. Build/install parity does
not establish extension authorization or kernel-module loading audit delivery.

### BSDCrypto daemon observability review (2026-10-27)

Native compilation retains crypto request completion, named-list and reclamation
probes; fourteen function/probe schemas and relative sites match Make. Existing
worker auditcmp_submit calls and audit client lifecycle remain compiled with native
libauditcmp. No probes/audit calls were changed or removed. Live audit delivery,
probe firing, crypto descriptor authorization and key lifecycle remain unqualified;
content/symbol comparisons do not establish those runtime properties.

### BSDCrypto policy test coverage (2026-10-27)

Eight maintained policy validation cases pass in the native candidate runtime.
They test allowed/invalid request profiles and selection constraints before provider
operations; they do not prove crypto algorithm correctness, audit delivery, live
probe behavior or descriptor authorization. No observability code was changed.

### BSDCrypto provider/lifecycle build coverage (2026-10-27)

The actual provider/lifecycle test code builds with Make-equivalent static symbols;
quota admission/release passes as a host-safe case. Provider and lifecycle were not
run, so no channel authority, crypto descriptor, audit delivery or live probe claims
follow. Existing test fixtures and production observability calls remain unchanged.

### BSDCrypto benchmark/evolution build coverage (2026-10-27)

The native latency benchmark preserves shared libchannel for request probes and the
maintained real client/provider code. Build/linkage equality is not a latency or
live-probe result. Separate next-version peer bindings compile and match Make;
real-channel negotiation, provider authorization and audit delivery remain runtime
gates. No instrumentation or source assertions changed.

### BSDCrypto installed contract tests (2026-10-27)

The complete archive now installs the unchanged manifest/provider-security shell
contract and its daemon-source/Makefile fixtures. Bytes and metadata match Make;
the shell was not executed. Runtime authorization, audit delivery and live probe
qualification remain separate gates; no test source or observability code changed.

### BSDExtension source review (2026-10-27)

Native daemon candidate carries bsdextension_provider.d and the existing shims
from bsdextension.c/reclaim.c: request completion, list, reclaim pass, accept retry
and worker rejection. Source review finds syslog events for ENSURE/STAT/RELOAD
and failure handling, but no direct audit submission in these daemon sources.
Review whether module loading, policy reload and reclaim decisions require explicit
audit records; logging alone does not establish audit integration. No production
instrumentation or policy changed. Live firing, delivery and runtime authority
remain untested by this build migration.

BSDExtension r4 build comparison matches eighteen function/probe schemas and
validated AMD64 sites against fresh Make, plus four dynamic globals and one DOF
record. This confirms carried-forward instrumentation structure, not live firing.

### BSDExtension reclaim logging/runtime gate (2026-10-27)

Four maintained reclaim cases terminate with SIGSYS for both Make and Bazel on
this host. Fresh Make tracing reaches cap_process feature detection then syscall
1011/ENOSYS while the reclaim paths exercise logging. Eight reclaim cases pass;
all fifteen allowlist and eight policy cases pass. Logging remains intact and
these failures remain runtime gates. No live module operation, provider channel,
probe firing or audit-delivery qualification follows from these tests.

### BSDExtension evolution/latency build coverage (2026-10-27)

Native helpers retain production client/provider code and shared libchannel for
latency instrumentation. Make-equivalent binaries and generated files do not
establish live probe firing or latency. The inherited-session regression passes
without provider requests. No observability code changed.

### libdevicecmp source review (2026-10-27)

No dedicated DTrace probes or direct audit submission were found in devicecmp.c.
Native targets preserve the existing client source and production FIDL transport.
Review whether open/list failures and reconnect/session transitions warrant client
instrumentation, and assess daemon/kernel audit coverage separately. No new probes
or audit calls were invented for the migration. Three argument-validation cases
pass before opening provider sessions; protocol runtime remains unqualified.

### BSDDevice source and probe review (2026-10-27)

The native daemon retains request-completion, open, list and worker-rejection
probes and existing syslog diagnostics. Six function/probe schemas and AMD64
patch sites match fresh Make output. No direct daemon audit submission was found;
review device grants/denials and descriptor rights against kernel/service audit
coverage. Source probes and logging were not changed. Seven policy tests pass,
including the OpenES attribute endpoint constraint, but do not qualify live OpenES,
device access, audit delivery or probe firing.

### BSDDevice test/helper coverage (2026-10-27)

Provider/lifecycle builds retain actual daemon sources and match Make symbols.
The quota case passes without provider activity. Evolution and latency preserve
real client/provider code; latency links libchannel shared for its probes.
Those builds are not live request, audit-delivery or latency qualification.
No observability source or test assertion changed.

### libnamespacecmp source review (2026-10-27)

No dedicated DTrace probe or direct audit submission was found in the client
source. Native targets preserve actual namespace FIDL calls and attachment logic.
Review namespace entry/destruction failures, session recovery and jail attachment
against provider/kernel audit coverage; build parity does not establish that
coverage. No instrumentation was added or removed. No live jail action executed.

### BSDNamespace source review (2026-10-27)

The native daemon candidate carries the maintained request completion, namespace
entry and reclaim-pass probes. Existing syslog/logcmp diagnostics remain intact.
No direct audit submission was found in bsdnamespace.c or reclaim.c; review
namespace creation/attachment/destruction and owner-map cleanup against provider
and kernel audit coverage. No instrumentation, policy or test logic changed.
Live jail activity, probe firing and audit delivery are not established by builds.

### BSDNamespace reclaim runtime limitation (2026-10-27)

Six naming and four owner-map cases pass. Cleanup reaches cap_process-dependent
logging and terminates with SIGSYS for both fresh Make and Bazel binaries on this
host; syscall trace records 1011/ENOSYS. Logging remains intact and the case stays
an unresolved matching-kernel runtime gate. No live provider/jail lifecycle or
audit-delivery/probe-firing claim follows from the successful build comparison.

### BSDNamespace helper build coverage (2026-10-27)

Native evolution and latency helpers preserve the actual client/provider and
shared libchannel. Make-equivalent generated code and linkage do not establish
live request tracing, namespace audit coverage or comparative latency. No source
instrumentation or test assertion changed.

### liboes source/probe review (2026-10-27)

Native liboes preserves the oesclient batch-read, corrupt-buffer and authorization
response probes in diagnostics.h/provider.d and their actual call sites. Four
function/probe schemas and validated AMD64 patch locations match fresh Make.
No live OES client creation, authorization response, event stream, probe firing
or audit delivery executed. No diagnostics or client source changed.

### liboes maintained test coverage (2026-10-27)

Nine cases across ownership, path, protocol and scripted broker-client suites
passed through Bazel. These exercise existing pipe/ioctl/allocation and broker
seams; they do not execute a live OES kernel stream or prove audit delivery or
probe firing. Test assertions and production diagnostics remain unchanged.

### liboes DTrace-disabled configuration (2026-10-27)

Fresh Make and native Bazel shared libraries both omit the DOF section with
DTrace disabled; their exported symbols and dynamic linkage match. Nine fixture
cases pass (three cached suites and one freshly executed suite). This adds no
live probe-firing or OES stream evidence.

### BSDFilesystem native daemon review (2026-10-27)

Preserved request message/validation/grant/reply and reclaim pass/destroy/snapshot
probes in the maintained request/layout code. Eight function/probe schemas and
AMD64 patch locations match fresh Make's DOF. No production instrumentation
changed. No live firing or audit-delivery qualification was performed; direct
security audit coverage remains a separate review item, especially grants and
storage mutations. DTrace metadata parity does not establish audit coverage.

### BSDFilesystem configuration test coverage (2026-10-27)

Seven maintained configuration cases pass under Bazel; the installation-specific
policy/layout case skips without explicit deployment inputs. The package fixture
checks do not exercise live ZFS or OES, request grant auditing, reclamation or
probe firing. Production code and test assertions are unchanged.

### BSDFilesystem OES/request test coverage (2026-10-27)

Two maintained factory seam cases pass; actual factory/session/handoff binaries
match Make but their live OES/channel behavior has not executed. The namespace
suite passes 38 cases and skips descriptor hardening (host kernel support) and
OES device alias (root). Provider binary parity does not qualify runtime grants
or probe firing. Real request-loop sources and logging remain intact; no source
instrumentation or assertions were altered to avoid host limitations.

### BSDFilesystem storage test limits (2026-10-27)

Nine quota cases and the unit-manifest admission case pass. Cleanup explicitly
expects failure for its documented storage ownership gate defect; that remains
unresolved. Worker shutdown fails on both Make and Bazel with PD_NOWAITPID/EINVAL
on the older host. No assertions or logging changed. Build parity for lifecycle,
anchor, abort, staging recovery and retention does not establish live storage
safety, audit delivery or reclamation probe firing.

### BSDFilesystem evolution and latency helpers (2026-10-27)

The helpers retain real client/provider sources and shared libchannel for the
latency executable. Generated bindings, symbols and linkage match Make; this does
not establish live protocol compatibility, latency, audit delivery or firing of
libchannel request probes. No instrumentation or assertions changed.

### BSDFilesystem DTrace-disabled build (2026-10-27)

Fresh Make and native Bazel omit the daemon DOF section when DTrace is disabled,
while matching symbols/linkage and preserving the unit policy payload. This is
build evidence only; no runtime test or live probe firing occurred in this variant.

### sysctlcmpctl and sysextctl source review (2026-10-27)

Neither control-program source declares direct DTrace probes or audit/syslog
calls in the reviewed source. Their executables have no DOF, matching Make;
client-library/daemon instrumentation remains downstream. Whether privileged
sysctl changes and extension lifecycle requests require additional direct audit
records remains a review item. No runtime audit-delivery claim follows from
binary parity; no instrumentation or application source changed.

### Service-control test runtime gate (2026-10-27)

The scripted helper binaries match Make. Shell cases did not execute successfully:
ATF setup hits a Capsicum assertion in staged dirname. No live sysctl/extension
operations, audit delivery or probe firing were qualified; existing source and
assertions remain intact.

### tracectl source review (2026-10-27)

The command source has no direct DTrace or audit/syslog calls in this review.
Native executable symbols/linkage and absent DOF match Make. Whether control
operations need direct audit records remains a review item; no live tracing,
policy enforcement or audit-delivery behavior has been exercised.

### libbsdfilesystem initial build (2026-10-27)

The native library preserves its real transport and downstream service/channel
libraries. Both Make and Bazel lack a library DOF section. No live grant, release,
mount, event or audit behavior was exercised. Direct observability requirements
remain to be reviewed with the client runtime tests; no instrumentation changed.

### libbsdfilesystem fixture test coverage (2026-10-27)

All six maintained request/reply/lifecycle/mount-wrapper cases pass with their
existing scripted transport. Production transport remains separate and unchanged.
This does not demonstrate live mounts, capability-channel grants, audit delivery
or firing of downstream probes.

### tzfsctl source review (2026-10-27)

No direct DTrace/audit/syslog calls were found in the control-program source;
absent executable DOF matches Make. Client/provider instrumentation is downstream.
Request/release/mount audit coverage remains a runtime review item. Only build,
linkage and package comparisons were performed; scripted shell and live storage
behavior were not executed. No production instrumentation changed.

### chio, devfs and conscontrol (2026-10-27)

Reviewed the utility sources during native build/install comparison. No direct
SDT/DTrace providers or userspace audit emission were found; absent DOF matches
Make for all three. Changer commands, devfs rule/permission changes and console
selection are operations for a future kernel audit-coverage review. Absence of
userspace instrumentation does not establish absence of syscall/kernel audit
coverage. No device operation, audit delivery or runtime tracing was exercised.
Evidence: /usr/obj/usr/src/bazel-device-utilities-20261027 and the corresponding
fresh component Make references. Instrumentation additions are not silently
introduced as part of the build migration.

### adjkerntz and ldconfig (2026-10-27)

No direct SDT providers or userspace audit emission were found in these program
sources; absent DOF matches Make. Adjkerntz retains its existing syslog calls.
Clock/timezone changes and library-hints replacement warrant an audit-coverage
review at the syscall/kernel boundary. Build parity does not prove event delivery
or policy coverage. No clock or host hints-file mutation was performed.

### pfilctl, recoverdisk and dumpfs (2026-10-27)

Source inspection found no direct SDT provider or userspace audit emission;
absent DOF matches the Make binaries. Packet-filter hook changes and disk/device
access remain candidates for kernel/syscall audit-coverage review. No policy
mutation, real-disk recovery, filesystem scan or audit-delivery test ran. The
native rules preserve current behavior rather than inventing probes during build
migration. Recoverdisk needs a disposable regular-file test before runtime claims.

### clri, fsirand, newfs_msdos and fsck_msdosfs (2026-10-27)

Clri/fsirand/newfs_msdos have no emitted DOF in either native or Make binaries.
Fsck_msdosfs preserves fatcheck check-start/check-done, generated headers and
static anchoring. Two schemas, argument mappings and site counts match Make;
amd64 probe sites validate. Live tracing and audit-delivery coverage remain open.
Inode changes, inode randomization and filesystem creation warrant kernel/syscall
audit-coverage review; the FAT32 runtime check used temporary regular files only.

### fsck_msdosfs provider-disabled build (2026-10-27)

Fresh native/Make DTrace-disabled binaries match 48 globals and lack DOF. The
normal build's two fatcheck schemas remain separately verified. Twelve maintained
filesystem regression cases have native declarations and installation parity;
none were run through ATF on the incompatible host. No live probe/audit claim.

### fsck dispatcher and umbctl (2026-10-27)

No direct SDT/userspace audit emission was found in their C sources; absent DOF
matches Make. Filesystem-check dispatch and modem configuration warrant separate
syscall/kernel audit-coverage review. No check dispatch, modem change, live probe
or audit delivery was exercised by the build/install comparisons.

### fsck_ffs (2026-10-27)

Native FFS preserves ffscheck phase-start/phase-done and its static DOF anchor.
One DOF record and both schemas match Make, with five probe and five enabled
sites per schema in main; amd64 site checks pass. Audit delivery and live probe
firing are untested. Installation preserves executable aliases; no repair was run.

### FFS runtime follow-up (2026-10-27)

The provider-disabled native FFS checker has absent DOF and matches Make.
Provider-enabled native and Make tools accepted reproducibly created UFS1/UFS2
regular-file images with forced read-only checking. No live DTrace consumer or
audit-delivery observation was attached; runtime success is not probe validation.

### growfs and tunefs (2026-10-27)

No direct SDT/userspace audit calls found; native and Make default binaries lack
DOF. Filesystem growth and tuning warrant a separate audit-coverage review. No
filesystem mutation, kernel audit delivery or runtime trace was exercised.
Growfs developer-debug buildability is not runtime observability qualification.

### mksnap_ffs (2026-10-27)

No direct SDT/userspace audit emission found; absent DOF matches Make. Snapshot
creation and privilege transitions need runtime audit-coverage review. Archive
setuid metadata parity is not installed setuid or audit-delivery qualification.

### etherswitchcfg and nos-tun (2026-10-27)

Neither source scan found direct SDT or userspace audit calls; native and Make
binaries both lack DOF. nos-tun retains existing syslog error/lifecycle messages.
Switch configuration, tunnel setup and teardown warrant runtime audit-coverage
review. No live device mutation, logging delivery or kernel audit was exercised.

### libibverbs (2026-10-27)

The migrated C-source scan found no direct SDT/DTrace, userspace audit or syslog
calls. RDMA device discovery, provider loading and resource operations require
runtime observability review. Symbol parity alone does not establish event or
kernel-audit delivery. No RDMA device was opened during this qualification.

### bnxtre and mlx5 userspace providers (2026-10-27)

The migrated C-source scan found no direct SDT/DTrace, userspace audit or syslog
calls. Provider registration and device/queue operations need runtime coverage
review; symbol comparison does not validate event emission or hardware behavior.
No RDMA device operations or live tracing were performed.

### libpcap capture backends (2026-10-27)

The BPF, netmap and RDMA backend scan found no direct SDT/DTrace, userspace audit
or syslog calls. Packet-capture authorization and observability require runtime
review; static/shared symbol parity does not establish kernel audit delivery.
No live capture or device access was exercised.

### pflogd (2026-10-27)

The maintained daemon uses vsyslog and retains chroot/setresuid privilege
separation. No direct SDT/DTrace or userspace audit calls were found; native and
Make binaries both lack DOF. Runtime qualification must cover logging delivery,
privilege transitions, capture and rotation. Compatibility macros for pledge and
unveil predate this migration and are unchanged; their presence is not evidence
of enforced confinement. No live daemon/audit checks ran.

### dumpon (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in the program;
absent DOF matches Make. Dump-device and encryption configuration warrant runtime
audit-coverage review. No dump configuration or encryption operation was exercised.

### libpjdlog and decryptcore (2026-10-27)

pjdlog retains syslog output and decryptcore's optional syslog mode. No direct
SDT/DTrace or userspace audit calls were found in the scanned sources. Decryption
error reporting, logging delivery and audit coverage require runtime checks;
binary/install comparisons do not establish these behaviors.

### swapon / swapoff / swapctl (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found; absent DOF
matches Make. Swap attachment/removal and encrypted backing-device operations
need runtime audit-coverage review. No swap state was changed during comparison.

### ffsinfo (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in ffsinfo.c or
the shared growfs debug source. Native and Make binaries lack DOF. This run
qualifies build/install artifacts only; no filesystem inspection was executed.

### GEOM frontend (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in core/geom.c
or misc/subr.c. Absent DOF matches Make. Storage-changing class commands need
runtime audit and privilege-coverage review after plugins are staged. Alias and
binary comparisons do not demonstrate confinement or audit delivery.

### GEOM label and multipath (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in the two class
sources. Label changes and multipath configuration need runtime audit-coverage
review. Build/install parity does not qualify device operations or audit delivery.

### GEOM mirror and zoned (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in either class
source. Mirroring and zoned-storage operations require runtime audit review.
Binary/install comparisons do not establish device behavior or audit delivery.

### GEOM part and raid (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in either class
source. Partition and RAID changes need runtime audit/privilege coverage review.
This run provides build/install artifact evidence only, not storage behavior.

### GEOM ELI (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in the userspace
class source or the four reused g_eli_crypto/g_eli_hmac/g_eli_key/pkcs5v2 sources.
Encryption/key management and device attachment need runtime audit/privilege
coverage review. Symbol and installation parity does not demonstrate audit
record delivery or cryptographic/device behavior.

### mdmfs and shutdown (2026-10-27)

mdmfs has no direct SDT/DTrace, userspace audit or syslog calls. Its helper/device
operations need runtime audit review. shutdown preserves existing BOOTTRACE and
syslog lifecycle/error calls through unchanged source compilation; neither
binary has DOF, matching Make. No direct userspace audit call was found. Capsule
shutdown delegation, log delivery, credentials and shutdown effects require
isolated runtime qualification; none was exercised on the host.

### reboot (2026-10-27)

Existing BOOTTRACE/syslog and pututxline calls remain in unchanged native source;
no direct SDT/DTrace or userspace audit call was found. Absent DOF matches Make.
The six ATF cases deliberately wrap sysctlbyname/pututxline and suppress lifecycle
side effects, so passing them is not trace/log/audit-delivery evidence. Nextboot
changes, real Capsule delegation, fallback authorization and lifecycle record
coverage require isolated VM qualification.

### mount_fusefs and quotacheck (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in either main
source, quotacheck's local preen.c, or its shared fsutil.c/utilities.c inputs.
Absent DOF matches Make. FUSE mount/helper authorization and quota metadata
updates need isolated runtime and audit-coverage review; artifact comparisons
do not establish those behaviors.

### fsdb (2026-10-27)

Make does not enable WITH_COVERAGE_DTRACE for fsdb; native output likewise lacks
DOF. The shared fsck phase provider is not silently enabled for this consumer.
No direct userspace audit/syslog or SDT calls were found in the local fsdb files.
Destructive inode/block edits need audit and authorization coverage review.
Read-only regular-file tests establish neither live tracing nor write auditing.

### dump and restore (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in either source
directory. Absent DOF matches Make. Backup data access, remote tape commands,
restore ownership/ACL handling and dumpdates updates need runtime authorization
and audit review. Artifact parity does not establish transport or restoration
correctness; no backup/restore operations ran in this qualification.

### routed and rtquery (2026-10-27)

Routed's existing syslog/vsyslog diagnostics remain through unchanged source;
no direct SDT/DTrace or userspace audit calls were found. Rtquery has no direct
syslog/SDT/audit calls. Both lack DOF, matching Make. Route changes, RIP packet
handling/authentication and log delivery need isolated network/runtime review.
Binary and package metadata comparisons do not establish those behaviors.

### rtsol and rtsold (2026-10-27)

The shared source preserves cap_vsyslog diagnostics. No direct SDT/DTrace or
userspace audit calls were found, and absent binary DOF matches Make. Casper
service libraries retain their own independently built tracing. Packet receipt,
interface-flag updates, script execution and log delivery need isolated runtime
and authorization/audit review. Compilation does not prove those boundaries.

### ddb (2026-10-27)

No direct userspace audit, syslog or SDT/DTrace calls were found in ddb's three
sources. Absent DOF matches Make. Installing/removing debugger scripts and reading
capture/core data require privilege/audit review on an isolated matching kernel.
The exact packaged ddb.conf is preserved; it was not applied to the host.

### savecore (2026-10-27)

Existing cap_vsyslog/vsyslog diagnostics remain in unchanged source; no direct
SDT/DTrace or userspace audit calls were found. Binary DOF absence matches Make.
Dump-device access, saved crash-data permissions, log delivery and live-dump
creation need isolated matching-kernel qualification. No crash data was read or
created, and the maintained log test has not run under Bazel yet.

### setkey (2026-10-27)

No direct SDT/DTrace, userspace audit or syslog calls were found in the command,
parser or reused PF_KEY/key_debug implementation. Absent DOF matches Make. Key
and security-policy updates, diagnostic disclosure and PF_KEY authorization need
runtime audit/privilege review on isolated systems. Generated-source and binary
parity do not establish secure key handling or kernel policy behavior.

### dhclient (2026-10-27)

The existing dhcplife state/script-start/script-done provider is preserved; DOF
schema/argument/site parity and amd64 site validation pass against Make. This is
not live probe-firing evidence. Syslog/Casper diagnostics remain in the source.
Privilege separation, packet handling, lease persistence and script execution
need isolated runtime/audit review; no DHCP operation was executed here.

### Dhclient parser tests (2026-10-27)

Native Bazel now executes the unchanged option-domain-search/date parser test.
The production daemon DTrace graph is unchanged. The parser test builds the
same subset as Make without enabling daemon lifecycle probes. PCP/VNET remains
installed with exclusivity metadata but needs a privileged runtime fixture;
a parser pass is not evidence of DHCP network or lifecycle-probe behavior.

### GEOM Gate programs (2026-10-27)

Reviewed ggatec, ggated, ggatel and their shared ggate.c. No explicit userspace
DTrace provider or BSM audit integration appears in these sources; the Make and
Bazel executable artifacts both lack a DOF section. Shared logging uses syslog
and is preserved. Review export authorization/configuration changes, attachment
and detach failures, and network connection lifecycle for audit/observability
coverage. Do not infer userspace coverage from libthr probes or kernel GEOM
instrumentation. Kernel module behavior and real device/network I/O remain
unqualified by these artifact/install comparisons.

### Standalone dnctl (2026-10-27)

No explicit DTrace provider or BSM audit calls found in the maintained dnctl
sources/Makefile; Make and Bazel binaries both lack DOF. The control path can
configure/delete/flush Dummynet state. Review kernel control-operation auditing
and error visibility before claiming end-to-end audit coverage. Native ABI test
passes; shell dry-run tests are present but blocked before their bodies by the
older-host Capsicum mismatch. No live shaper operation was exercised.

### HAST daemon and control utility (2026-10-27)

Reviewed hastd/hastctl sources and Makefiles: no explicit userspace DTrace
provider or BSM audit hooks found, and both native/Make executable pairs lack
DOF. Existing pjdlog role changes, worker termination and errors are preserved.
Review control authorization, role transitions, replication reconnect/failover,
and metadata-changing operations for audit/probe coverage. Artifact and parser
comparisons do not establish runtime failover or kernel/storage observability.

### Ping program (2026-10-27)

No explicit DTrace provider or BSM audit hooks found in the maintained ping
sources; Make and Bazel binaries both lack DOF. Preserve existing Casper DNS
and Capsicum integration. Review audit coverage of privileged raw-socket setup
and DNS delegation in their implementing subsystems; the build comparison does
not demonstrate runtime audit events. Setuid metadata is preserved in the
archive. No network or packet-injection test was performed in this increment.

### reroot_seed internal helper (2026-10-27)

No explicit userspace DTrace or BSM hook in the helper; full Make/native static
binaries contain no DOF. Existing LOG_AUTH emergency syslog and RB_REROOT request
are preserved. Audit the privileged kernel root-transition path when qualifying
init; symbol/build parity alone does not prove audit or lifecycle behavior.
The helper was not executed.

### Native init embedding (2026-10-27)

Native init retains maintained source and logging behavior; Make/native binaries
lack DOF. This increment verifies declared seed embedding and installation
metadata, not PID1 lifecycle, login/audit events or root-transition logging.
Review those behaviors in a booted matching-system qualification. No init or
reroot_seed execution was performed.

### resolvconf generated scripts (2026-10-27)

All generated shell payloads match Make. This template migration adds no
instrumentation; runtime resolver updates and subscriber restarts need separate
operational/audit review. No subscriber or resolver mutation was executed.

### OpenBSD-derived pfctl (2026-10-27)

No explicit userspace DTrace provider or BSM audit call found in pfctl/glue C
sources; Make/native binaries lack DOF. Audit control-operation coverage at the
PF ioctl/kernel boundary for rule loading, table changes, jail/ether extensions
and authorization failures. Artifact/parser parity establishes no runtime
firewall audit coverage. No PF control command was executed in this increment.

### libveriexec (2026-10-27)

Native graph preserves exec_script, grantbylabel and veriexec check/get sources.
Artifact parity does not exercise their kernel MAC calls or script execution.
Review denial and authorization audit behavior at those kernel boundaries when
performing runtime qualification; library build success is not enforcement proof.

### BearSSL (2026-10-27)

Native declarations carry the maintained cryptographic sources unchanged.
Symbol/link and installation checks do not establish crypto runtime correctness
or audit coverage. Review security-event logging at secureboot/veriexec consumers
when those components are converted; upstream crypto runtime tests remain pending.

### BearSSL optional crypto follow-up (2026-10-27)

Upstream crypto runtime tests now pass with SSL enabled, subject to the recorded
Power8 unavailability. No logging/probe behavior was added or removed. These
known-answer/arithmetic tests do not establish audit coverage, TLS integration,
trust selection or enforcement at secureboot/veriexec consumers.

### libsecureboot trust initialization (2026-10-27)

Native tests exercise real certificate decoding/anchor construction and cached
initialization, not signature/chain enforcement. Review found ve_test_hash in
vets.c prints Failed but does not accumulate that failure into ve_self_tests'
return value; its return currently counts verified certificates/OpenPGP results.
Track and qualify error propagation and callers before claiming enforced
cryptographic self-tests. This migration has not modified that behavior.

### veriexec command and manifest parser (2026-10-27)

The native graph preserves production sources and generated parser/lexer.
Four maintained tests verify valid input, hash-length rejection, ioctl failure
propagation and recovered syntax errors via the existing ioctl recorder. They
do not exercise kernel MAC audit events, manifest loading or denial enforcement.
Review those runtime/audit paths on a qualified system; no kernel state changed.

### libsecureboot hash-result follow-up (2026-10-27)

The hash self-test return-status weakness noted above is fixed: failed KATs
return cached zero before later signature successes. Native clean/SHA256/SHA384
corruption cases pass. Existing failure messages are retained. Strict-mode caller
checks zero; verify_prep/tvo still intentionally ignore the return. Their policy
and complete boot enforcement have not been qualified by this unit-level fix.

### Signed-file and trust-rotation test (2026-10-27)

Native verification emits existing success/rejection diagnostics during 25
in-process signed-file checks. Return values and verified payload bytes are
asserted; no audit event completeness claim is made. Kernel manifest loading,
system policy changes and firmware logging are outside this test's scope.

### freebsd-version (2026-10-27)

Native generation preserves the maintained shell program. Default/-u reporting
was exercised; no kernel/jail command was run. This utility gains no new tracing
or audit behavior. Kernel/jail query and deployment-version consistency checks
remain part of system qualification.


## zsh ABI-table increment (2026-10-27)

Native table generation preserves upstream algorithms and target preprocessing.
It does not yet build zsh. Existing `trace_pressure.h`, `FIVEBSD_TRACE`,
`WITH_DTRACE` and `zsh_provider.d` integration must be preserved when adding
native compilation/linking. No probe additions/removals or runtime audit
coverage claims follow from the four byte-equal generated files.


### zsh executable follow-up (2026-10-27)

The native amd64 executable preserves all nine Make DOF probe records, compared
by parsed provider/function/name, argument types and site counts. Source
instrumentation is unchanged; runtime attachment/firing is not yet tested.
Evidence: `bazel-zsh-runtime-r5-20261027/qualification/binary-parity.json` under
`/usr/obj/usr/src`. The noninteractive shell smoke test passes but does not
establish job-control/pty tracing or audit integration coverage.


### zsh installation follow-up (2026-10-27)

The full native installation now preserves Make's debug split/link and all
configuration/completion/manual payloads. No instrumentation sources changed.
The earlier nine-record DOF comparison remains executable-level evidence;
probe firing and interactive behavior still require runtime qualification.


### zsh upstream runtime and disabled probes (2026-10-27)

The native DTrace-enabled candidate passes 62 of 63 retained upstream groups;
privileged behavior is skipped under the current UID, and conditional host
limitations remain logged. W02/W03 job-control groups run successfully, but
these tests do not attach DTrace consumers or prove probe firing. The explicitly
DTrace-disabled candidate matches Make and contains no DOF section. No probe
source was removed or rewritten to achieve these results.


### zsh static-root follow-up (2026-10-27)

The static non-PIE native zsh retains all nine Make DOF records and passes its
smoke test without candidate shared libraries. This checks instrumentation
retention through static linking; runtime probe attachment/firing remains
unqualified. No observability source or test assertion was weakened.


## libsm/rmail native migration (2026-10-27)

The maintained component Makefiles contain no DTrace provider integration;
native migration adds/removes no instrumentation. rmail's observed paths are
usage/input rejection only; successful sendmail handoff and mail-delivery
logging/audit behavior are unqualified. Review those paths with the mail-service
integration tests rather than inferring coverage from library tests or packaging.


## csh native generator/executable increment (2026-10-27)

The maintained csh Makefile has no DTrace provider step. The native migration
preserves its source set and generated inputs without instrumentation changes.
The arithmetic/array smoke test does not cover interactive job control,
password/lock behavior using crypt, signal/audit integration or login startup.
Keep these as runtime qualification gaps, not inferred coverage from linking.


### csh installation/iconv-stub follow-up (2026-10-27)

Both csh/tcsh executable names retain valid split debug linkage in default and
iconv-disabled/no-examples archives. Configuration/catalog payloads match Make.
The smoke test still covers arithmetic/arrays only; locale switching, login,
interactive job control, lock/password paths and audit behavior remain outside
this runtime evidence. No instrumentation or production shell source changed.


### csh static/NLS-disabled and bin test gaps (2026-10-27)

Static csh retains matching symbols and split debug linkage without dynamic
runtime dependencies. The smoke scope remains arithmetic/arrays. The bin
file-presence inventory exposes 19 missing test BUILD directories; no audit,
probe or service behavior coverage should be inferred from 42 component BUILD
files. Preserve privilege/jail requirements when integrating those test suites.


## cat ATF integration (2026-10-27)

The maintained suites now expose all 13 cases and fixtures natively. No probe
source changed; test packaging retains the executable debug link. Every case
currently fails in helper initialization with a Capsicum assertion reproduced
by Make-built dirname as well. Consequently none of the cat option/body tests
or probe behavior gains runtime qualification from this run. Failure logs and
cross-build-system reproductions are retained; no skip/fallback was added.

## echo test integration (2026-10-27)

Both maintained cases now select the candidate explicitly, retaining installed
/bin/echo defaults. No production executable, probe or audit behavior changed.
Installation/debug parity passes; both ATF bodies remain unexecuted because
helper startup hits the diagnosed host/SDK Capsicum ABI mismatch.

## bsdcat (2026-10-28)

No program-local DTrace or audit calls were found in the imported cat C/header
sources. It consumes the existing native libarchive graph, including that
library's configured instrumentation; this change adds no probes and does not
qualify probe attachment. Eighteen compression/CLI cases pass, 1,051 assertions,
zero skips. Program/harness globals, dependency order, generated registry and
both installed debug links match Make. The local suite still uses host shell
utilities/libc; full runtime closure and performance remain open.

## stdbuf/libstdbuf (2026-10-28)

These two small C components contain no DTrace providers or audit calls.
No instrumentation was removed or added. The preload constructor's output
buffering is exercised in eight native child-process cases; debug links and
binary metadata match Make. Installed absolute-path integration, stdin and
privileged-loader behavior remain unqualified. A preload library must avoid
unnecessary dependencies and namespace pollution; native libstdbuf retains
Make's sole libc dependency.

## xstr, revoke, tcopy (2026-10-28)

No program-local DTrace or audit call integration was found in these source
files, and none was added or removed by the native build declarations. revoke
calls the kernel revoke syscall; its syscall audit behavior and live-device
access revocation are not exercised by usage/nonexistent-path checks. tcopy's
SIMH-TAP fixture checks do not qualify physical device errors, file sets,
signals, privileges or tape-driver instrumentation. xstr's file/stdin and
persistent table outputs match Make. All three executable debug links match
their packaged debug files. Runtime comparisons are retained outside Bazel's
test catalog; converting them to maintained native tests remains work.

## Kernel config tool (2026-10-28)

No tool-local DTrace/audit call sites were found in config's C/C++, parser or
lexer sources. This migration preserves config output, including configured
kernel option headers, without changing instrumentation policy. GENERIC and
-g output inventories match Make, but no kernel/module probes were compiled,
loaded or exercised. Kernel audit/DTrace retention remains a separate gate.

## install / bootstrap_install (2026-10-28)

All five installcopy probes are preserved with matching argument schemas and
site counts: range-start/done, fallback and sync-start/done. Normal copy paths
were exercised but probes were not attached or counted at runtime. Bootstrap
source selection intentionally excludes probes and copy_file_range, as Make
does. No new audit hooks were added. Ownership and identity-database tests use
-U/private files and do not qualify privileged installs or account changes.
The full maintained ATF suite is packaged, with native runtime registration
still pending; no assertion or kernel-compatibility fallback was introduced.

## mtree / nmtree (2026-10-28)

No local DTrace/audit integration was found in the imported mtree/mknod C
sources. None was removed or added. Native conversion/merge cases pass and
private-tree checks observe hash/mode/missing/extra differences. Missing/extra
entries retain the maintained exit-0 behavior with stdout diagnostics; this
must be considered by future integrity-check callers. No completeness or
security conclusion can be drawn from that exit code alone. These tests do
not qualify privileged mutation, ownership/flags, or full ATF coverage.

## libkldelf / kldxref (2026-10-28)

No local DTrace/audit sites were found in these sources. All eight relocation
backend registrations are retained through linker sets in both native shared
and static-bootstrap consumers. Hints generation and failed-output preservation
were checked on private copies of two amd64 modules; no kernel modules or
probes were loaded. Other architecture relocation paths, live loader behavior
and kernel instrumentation retention remain separate qualification gates.

The maintained PNP, explicit-input and hints-failure audits now execute through
six Bazel test targets for native and bootstrap kldxref (37 checks per variant).
They exercise malformed metadata and failed output updates without loading
modules. This expands utility error-path coverage; no DTrace/audit sites were
added, removed or runtime-attached, and kernel instrumentation remains untested.

## Core kernel object interfaces (2026-10-28)

Native generation preserves all C/header bytes from makeobjops for the eight
core sys/kern interfaces when invoked with identical source basenames. It does
not filter methods or substitute stub implementations. Kernel compilation and
runtime dispatch, tracing and audit behavior have not been exercised by this
output-generation comparison.

## Vnode interfaces (2026-10-28)

Native vnode generation is byte-equal to all four Make-generated artifacts.
The C output preserves 166 SDT definitions and 166 call sites; vnode_if.h
preserves 166 declarations and 116 inline call sites. There is no filtering or
stub substitution. This confirms source preservation only: kernel compilation,
linker retention and live DTrace attachment remain untested. The generator does
not supply per-operation audit-record integration; broader audit behavior lives
in its callers and has not been qualified by this generation comparison.

The same makeobjops comparison now covers all 132 current object interfaces,
including devices and non-host architectures: 264 byte-equal C/header outputs.
makeobjops does not itself generate SDT or audit sites. No instrumentation was
added or removed; driver instrumentation and audit behavior must still be
checked when the corresponding implementation objects are compiled and linked.

## Actual GENERIC layout objects (2026-10-28)

Native genoffset/genoffset_test/genassym retain the current GENERIC options,
including HWPMC_HOOKS. Their symbol sizes and generated offsets/constants match
a fresh Make reference. These are layout objects, not instrumentation-bearing
kernel runtime implementations; this does not qualify live PMC, DTrace or audit
behavior. No option was removed to avoid declaring its headers.

## Generated kernel config/env/hints objects (2026-10-28)

CTF conversion retains DWARF for GENERIC's debug configuration. CTF labels,
types/data records and allocated payload sections match Make, including the
embedded kernel configuration. These data objects add no probe sites; kernel
CTF merging, debugger use and live DTrace/audit behavior remain unqualified.

## Compiled vnode implementation (2026-10-28)

Native GENERIC vnode_if.o retains 166 SDT probe symbols, 166 probe-set pointers,
415 argument-type pointers and 5312 bytes of tracepoint records. All allocated
section bytes and canonical relocation records match Make, as do CTF dumps;
DWARF is retained. This advances beyond source-only preservation evidence.
Kernel final-link retention, live SDT attachment and audit behavior are still
unqualified. Generated assertion filenames are normalized by compiler flags,
not by filtering comparison output or disabling assertions.

## Native kernel version data (2026-10-28)

GENERIC vers.o now retains CTF and DWARF, matching Make's allocated data and
CTF label/type/data dumps. This data object adds no probe sites. Compiler and
source identity are explicit build inputs; supplied provenance is not verified
boot or a cryptographic source attestation. Final kernel CTF merging, debugger
access and live instrumentation remain open.

## nullfs module compilation (2026-10-28)

All three native module objects retain Make-equivalent allocated data and
relocations. null_subr.c defines four SDT probes (cache hit/miss, node start/done)
and one provider; the probe/argument sets retain 4/7 pointers and tracepoints
retain 12 relocations. null_vfsops.c retains 3 module-metadata records. CTF
labels/types/data match and DWARF remains present. No new direct audit callbacks
were added; filesystem audit integration must be evaluated through the complete
VFS/system path. Native module linking and live SDT/audit qualification are open.

## Linked nullfs candidate (2026-10-28)

Native linking/export processing preserves Make-equivalent SDT/module data and
canonical allocated relocations. CTF label/type/data dumps match after merge,
and debuglink CRC is valid. The runtime retains its required loader symbol table,
while only the two declared vnode-operation symbols remain global exports.
Native kldxref emits the same linker.hints as for Make. This is a static linked
module check, not a module load, live probe attachment, filesystem or audit test.
