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

## Open CTF correctness failure (2026-10-28)

The registered nullfs artifact test exposes wrong symbol/type associations after
export localization in BOTH current Make and native outputs. Earlier equal dumps
were equal but wrong: null_vnodeops maps to sdt_provider rather than vop_vector,
and some SDT variable types are wrong. No claim of valid live DTrace types follows
from previous parity. A late merge with -f fixes this module but misassigns a
same-named static/global collision fixture; that prototype was removed. Exact
ELF symbol identity must be preserved through localization before qualification.

### CTF localization reproduction expanded (2026-10-28)

The maintained `tools/build/bazel/tests/ctf/localization-audit.py` diagnostic
now reproduces incorrect data **and function-return** types with exported,
localized and same-name static symbols. Both installed-tool and Bazel-native
runs pass their source-type baseline and fail both the current ordering and
the rejected fuzzy-merge alternative. Native evidence is retained at
`/usr/obj/usr/src/ctf-localization-native-r2-20261028`. This is additional failure
evidence, not a fix or module qualification. See `tests/ctf/LOCALIZATION.md`
under the Bazel tooling for scope and next implementation requirements.

### CTF v2 reader discrepancy found during module qualification

The format matrix exposed `cddl/contrib/opensolaris/common/ctf/ctf_open.c`
rounding each function-section record to four bytes in `init_symtab`. The
maintained ctf(5) function-section description, ctfdump, ctfmerge input reader
and kernel FBT reader use packed records; only the following type section
requires alignment. The new objcopy candidate and independently validated
fixtures now use packed records. The existing libctf reader discrepancy is
not fixed or runtime-qualified here and should receive a focused API regression
before a separate fix. Native generated CTF is version 3, where record widths
make this discrepancy invisible. Do not infer v2 consumer correctness from
the passing objcopy/ctfdump matrix.

### fdescfs native module review (2026-10-28)

The two fdescfs C sources have no explicit SDT probe declarations or direct
AUDIT calls. This is carried forward unchanged from Make, not evidence
that filesystem operations bypass the kernel's common audit hooks. Assess
whether component-specific probes are useful separately; no probes or
audit behavior were added or removed for the build migration.

### unionfs native module review (2026-10-28)

`union_subr.c` declares and fires `copyup__start` and `copyup__done`.
The native GENERIC build preserves both probes. All SDT sections, their
relocations, and runtime symbol listings match the Make reference in
`/usr/obj/usr/src/bazel-filesystem-modules-20261028/qualification`.
This is artifact evidence; no live DTrace firing was tested.

### tmpfs/pseudofs conversion in progress (2026-10-28)

Tmpfs declares 11 SDT probes across rename/node/capacity/vnode/reclaim/resize.
Its SDT section bytes match Make in the initial artifact comparison, but
rodata/relocation/CTF mismatches remain under investigation. It includes
audit.h but the inspected sources contain no direct AUDIT_* calls. Pseudofs
has no explicit SDT or AUDIT_* calls. These observations do not establish
common VFS audit coverage; live probe/audit qualification remains open.

Tmpfs/pseudofs follow-up: header identity and CTF ordering mismatches were
resolved without source changes. Complete runtime symbol and relocation
listings now match Make; text/data/rodata and raw CTF also match. Evidence:
`/usr/obj/usr/src/bazel-tmpfs-pseudofs-ctf-20261028/qualification`. Live probe
firing and common VFS audit coverage remain untested.

### GEOM nop/gate (2026-10-28)

The inspected g_nop.c and g_gate.c have no explicit SDT_* declarations or
AUDIT_* calls. Their complete runtime symbols and relocations match Make;
no observability source changes were made for migration. Assess useful
GEOM fault-injection and gate I/O instrumentation separately, together with
common GEOM tracing/audit coverage. No live I/O or probe attachment was run.

### GEOM Linux LVM, multipath and zoned (2026-10-28)

Multipath declares six SDT probes: config restore/remove/disconnect/fail/taste
and io restart. Its SDT probe/argument/tracepoint sections and complete
symbol/relocation listings match Make in the native artifact comparison.
No live probe firing or failover was exercised. Inspected Linux LVM/zoned
sources have no explicit SDT_* or AUDIT_* calls; migration adds/removes none.
Assess common GEOM instrumentation and useful component-specific coverage
separately. Evidence: bazel-geom-expanded-20261028/qualification under /usr/obj/usr/src.

### GEOM mirror (2026-10-28)

Neither inspected g_mirror.c nor g_mirror_ctl.c declares SDT_* or AUDIT_*
calls. The native module's complete runtime symbol and relocation listings
match Make; no instrumentation changes were made. Assess mirror failover,
resync and common GEOM tracing/audit coverage separately. Runtime behavior
and live instrumentation remain unqualified.

### GEOM GPT (2026-10-28)

The inspected g_part_gpt.c has no explicit SDT_* or AUDIT_* calls. Native
module symbols/relocations match Make. Generated interface integration does
not alter instrumentation. Assess common GEOM/partition auditing and useful
GPT-specific probes separately; no live partition operation was performed.

### BSD/EBR/MBR partition modules (2026-10-28)

The inspected three scheme sources and geom_bsd_enc.c have no explicit
SDT_* or AUDIT_* calls. Native symbols and relocations match Make. No
instrumentation was added or removed; common partition/GEOM audit and
probe coverage needs separate runtime review. Evidence is retained under
/usr/obj/usr/src/bazel-partition-modules-20261028/qualification.

### GEOM label (2026-10-28)

The ten inspected g_label*.c sources contain no explicit SDT_* or AUDIT_*
calls. Native runtime symbols and relocations match Make. No probes/audit
behavior were changed; common GEOM discovery instrumentation and useful
format-specific label probes require separate review. Runtime label detection
was not exercised. Evidence: bazel-geom-label-20261028/qualification under /usr/obj/usr/src.

### GEOM flashmap (2026-10-28)

No explicit SDT_* or AUDIT_* calls were found in geom_flashmap.c. Native
symbols/relocations match Make with export-all semantics; no instrumentation
was changed. Common GEOM tracing and flash slicing runtime coverage remain
to be reviewed and exercised.

### GEOM uzip (2026-10-28)

No explicit SDT_* or AUDIT_* calls were found in the inspected uzip C sources.
The enabled native module matches Make symbols/relocations. Disabling ZSTDIO
removes the zstd implementation and feature symbols as configured. No source
instrumentation was altered; live compression I/O, error paths and common
GEOM tracing/audit coverage still need qualification.

### GEOM RAID (2026-10-28)

The inspected RAID C sources contain no explicit SDT_* or AUDIT_* calls
(despite g_raid.c including sdt.h). Runtime symbols/relocations match Make.
Metadata detection, rebuild/resync, degraded I/O and fault handling are
candidates for instrumentation review alongside common GEOM coverage. No
live array, fault-injection or audit behavior was qualified.

### GEOM ELI (2026-10-28)

The nine inspected ELI sources have no explicit SDT_PROBE_DEFINE or AUDIT_*
calls. Native runtime symbols/relocations match Make without instrumentation
changes. Encryption worker, authentication failure and key lifecycle coverage
require separate review with common GEOM/crypto tracing and audit hooks.
No encrypted storage operation or live probe/audit behavior was tested.

### MAC DDB/priority/NTP (2026-10-28)

mac_ddb registers init, DDB command registration/execution and KDB backend
checks. mac_priority and mac_ntpd register privilege-grant hooks. The inspected
sources contain no explicit SDT_* or AUDIT_* calls; common MAC/audit hooks
need runtime review. Native symbol and relocation listings match Make,
preserving registrations. No policy grants/denials or audit records were
exercised. Evidence: bazel-mac-modules-20261028/qualification under /usr/obj/usr/src.

### MAC port ACL/PIM (2026-10-28)

Port ACL registers init/destroy and socket_check_bind; PIM registers priv_grant.
Neither inspected source has explicit SDT_* or AUDIT_* calls. Native symbol
and relocation-record comparisons preserve hook registrations. Common MAC
audit/tracing and live bind/privilege behavior need runtime review; no policy
module was loaded for this build qualification.

### mac_do (2026-10-28)

Configuration and rule__grant SDT probes are retained with byte-matching
provider/probe/argument/tracepoint sections and relocation listings. Registered
hooks include init/destroy, credential setcred enter/check/exit and privilege
grant. Artifact parity does not establish credential authorization or audit
behavior. Live grants/denials, jail interaction and probe firing remain open.
Evidence: bazel-mac-do-20261028/qualification under /usr/obj/usr/src.

### mac_abac (2026-10-28)

Native ABAC preserves all provider/probe/argument/tracepoint section bytes
and relocation listings against Make, including rule evaluation, grant/deny,
rule-management and label/extattr probes. Existing policy source remains
unchanged. Live probe firing, rule decisions and audit-record semantics have
not been tested by the build comparison. Evidence: bazel-abac-20261028/qualification
under /usr/obj/usr/src.

### Veriexec fingerprint modules (2026-10-28)

The four native SHA registration modules preserve their original source and
crypto implementations. They contain no SDT probes or direct audit calls.
Core Veriexec already defines fingerprint status/start/done probes in
veriexec_metadata.c and capimage verification probes in veriexec_capimage.c;
these core sources are not qualified by the fingerprint module builds.
Review live registration/unregistration, verification failures and audit
coverage when converting and testing the core module. Do not add per-block
crypto probes merely to increase instrumentation counts. No live module
load, verification decision or probe firing is claimed here.

### Core Veriexec native build (2026-10-28)

All five core SDT definitions (fingerprint status/start/done and capimage
verify start/done) retain Make-identical provider/probe/argument/tracepoint
sections in both diagnostic compiler settings. The lookup paths retain their
AUDITVNODE1 flags. Artifact comparison does not establish live audit events or
probe firing. Registration, invalid signatures, vnode replacement/cache
invalidation, key changes and concurrent verification still need runtime
qualification with the completed kernel. VERIFIED_EXEC_DEBUG currently has
no source consumer; toggling its preserved build setting does not change
runtime behavior or observability.

### Capability accounting, identity and coalition (2026-10-28)

Accounting's two SDT definitions and coalition's twenty-two definitions retain
Make-identical provider/probe/argument/tracepoint sections. Identity currently
has no SDT definitions or direct audit calls. Track identity operation grants,
denials and credential changes for an observability review; do not count
matching absent sections as probe coverage. Accounting and coalition runtime
limits, cleanup/races, deny reporting and audit delivery remain untested by
these artifact comparisons. No instrumentation or policy source was changed.

### Capability node and channel modules (2026-10-28)

Node's call__done/deny probes and channel's create/forward/handler__done/state
probes retain Make-identical SDT sections. The channel-create syscall registers
sy_auevent=AUE_NULL in existing code. Record that as an audit coverage question
for syscall creation/denial and related descriptor operations; preserving its
build does not establish audit coverage. No audit event or SDT policy was
changed during conversion. Live probe firing, syscall/module registration,
authorization and descriptor lifecycle/concurrency remain unqualified.

### Capability isolation, mount and system (2026-10-28)

Preserved all twelve isolation probes, two mount probes and three system
probes; their SDT section bytes match Make. The system policy registers
system_check_auditon and system_check_auditctl hooks. These constrain audit
control operations; their presence does not prove audit record generation
or delivery for every capability action. Live allow/deny decisions, probe
firing, audit control behavior and jail/mount/network lifecycle still need
runtime tests. No security or instrumentation behavior was altered here.

### Core capability and capprotect (2026-10-28)

Core source inventory retains 33 core, five device and four label SDT
definitions (42 total); the kern source uses the provider without defining
additional probes. Capprotect retains three definitions. All SDT sections
match Make after export processing. Service/mint/reply/revoke, descriptor
transfer, label transitions, protected operations and failure-path probe
delivery still need runtime qualification, including races and resource
measurements. Process/authority built-ins remain a separate kernel review;
module artifact parity does not establish their audit/probe coverage.

### Capability process and authority built-ins (2026-10-28)

Neither source currently defines SDT probes. Review process-context creation,
inheritance/teardown and authority token creation/revocation/expiry for useful
probe and audit coverage during runtime qualification. Object-level parity
preserves current behavior; it does not prove observability or enforcement.
No probes, callbacks or audit behavior were changed during conversion.

### MAC framework control group (2026-10-28)

The seventeen new built-in object comparisons include all allocated SDT
sections and their relocation records. Existing audit-control policy checks
and MAC_CHECK_PROBE definitions remain in the source. mac_kdb has no direct
probe definitions in this group; review debugger/policy observability in the
context of its existing call paths. Live MAC dispatch, policy registration,
lock context, rejection/error paths and audit event delivery remain open.
The four network/VFS groups are not covered by this object qualification.

### MAC network and VFS framework objects (2026-10-28)

mac_net, mac_inet, mac_inet6 and mac_vfs retain their allocated SDT sections
and relocation records byte-for-byte relative to Make. The complete 21-source
GENERIC framework inventory now has native object comparison evidence.
Network packet/label lifecycle, VFS operations, mapping/revocation paths,
policy registration/dispatch and live audit/probe behavior still require a
linked test kernel. Existing probes were preserved, not expanded.

### GENERIC audit kernel object group (2026-10-28)

All fourteen selected sources retain their allocated data and runtime
relocations; audit_pipe.c retains seven auditpipe probes (open, close, submit,
append, drop, ioctl, read). Matching compiled audit code is not evidence of
live event delivery or completeness of event selection. Qualify pipe/trail
output, selection, queue limits/drop, rotation, storage failure and MAC
interaction on a completed test kernel. The conditional audit_dtrace.c
DTAUDIT/DTRACEALL build and dynamic audit provider remain outstanding.

### MAC test modules (2026-10-28)

mac_test and mac_test_hooks contain no direct SDT definitions. Their existing
sysctl counters/controls and assertions are test instrumentation, preserved
by native artifact parity. mac_test_hooks exposes per-hook invocation
counters and denial controls. Later runtime tests must demonstrate counter
increments and the requested denials on the actual linked test kernel;
compilation does not establish hook invocation, race safety or audit delivery.

### openES module (2026-10-28)

All compiled SDT sections match Make; oes_event.c contains nine direct probe
definitions. The existing authorization-denial AUDIT_ARG_TEXT annotation in
oes_mac.c and process audit identity capture in oes_client.c are preserved.
Neither compiled parity nor these call sites establish actual event/audit
delivery. Runtime qualification must exercise allow/deny, client disconnect,
timeout modes, queue/drop pressure and cache invalidation with ABAC enabled.
No probes, audit behavior or security policy were changed in this conversion.

### Built-in ABAC and openES variants (2026-10-28)

The twenty built-in objects preserve all allocated SDT sections and runtime
relocations relative to their maintained kernel Make recipes. This extends
artifact evidence beyond the earlier loadable module variants, without
claiming live policy interaction. Label/credential transitions, rule changes,
openES client failure/timeout, cache invalidation, hook ordering and audit
output must still be exercised on a linked test kernel. No instrumentation
or enforcement behavior was changed.

### Complete GENERIC capability built-ins (2026-10-28)

All fifteen selected capability sources now have native built-in object
comparisons, preserving allocated probe sections and runtime relocations.
This extends earlier module evidence and retains the recorded identity,
process/authority and channel-create audit questions. Live kernel dispatch,
service/module coexistence, credential transitions, descriptor lifecycle,
revocation/timeout races and audit/probe delivery remain unqualified. No
instrumentation or security source behavior was changed.

### Veriexec/parser/SHA2 built-in variants (2026-10-28)

Native object comparisons preserve the core verification probes and all
allocated runtime sections relative to Make. The parser contains no direct
SDT or audit call sites; review malformed input, load/reload and acceptance/
rejection diagnostics during runtime qualification. Cryptographic primitives
need functional vectors and integration checks, not per-block probes added
solely for coverage counts. Live trust/key changes and verification/cache
behavior remain open. No instrumentation or policy source changed.

### libkern common support routines (2026-10-28)

The forty-eight converted support objects match Make code/data and runtime
relocations. Avoid adding probes to each hot string/memory/crypto helper for
coverage counts; test behavior through vectors and instrument meaningful
call sites where needed. Timing-sensitive helpers still need appropriate
functional/performance review beyond artifact parity. Random-provider and
x86 CRC implementations remain outside this object group.

### Remaining GENERIC libkern objects (2026-10-28)

arc4random and x86 CRC object code/CTF/relocations match Make within the
complete fifty-object aggregate. Live entropy initialization/reseeding,
random-provider behavior and CPU dispatch/CRC vectors still need execution
tests. Do not infer entropy quality or instruction compatibility from a
successful compile. No runtime source or instrumentation policy changed.

### devfs kernel object group (2026-10-28)

The five native objects preserve Make's code/data and runtime relocations,
including existing MAC vnode association, relabel/update and symlink hooks.
Do not infer live hook invocation from artifact parity. Runtime qualification
must cover node lifecycle, devfs rules, jailed views, device I/O and label
propagation; assess audit/probe coverage along those paths. No instrumentation,
filesystem policy or source behavior changed in this build conversion.

### tmpfs and pseudofs built-in variants (2026-10-28)

Native built-in object comparisons preserve all allocated sections and runtime
relocations against Make, extending the earlier module artifact evidence.
Live VFS/MAC/audit integration, vnode cache lifetimes, concurrent teardown and
memory-pressure behavior still need a linked test kernel. Review tracing at
those operations without interpreting build parity as executed hook coverage.
No filesystem or instrumentation source behavior changed.

### System V IPC kernel group (2026-10-28)

Native objects preserve existing SDT sections and runtime relocations,
including message wait/wake and shared-memory lifecycle probes, plus existing
AUDIT_ARG_SVIPC call sites. Live delivery is not established by compilation.
Runtime coverage must include success/denial, blocking interruption, resource
limits, IPC removal, jail isolation and semaphore undo on process exit. No
IPC policy, instrumentation or runtime source changed.

### Shared memory and synchronization built-ins (2026-10-28)

Native objects preserve allocated sections and runtime relocations against
Make, retaining configured HWPMC/KTRACE and existing lock instrumentation.
This does not demonstrate lock ordering, contention/wakeup behavior, audit
output or shared-memory lifecycle. The open ZFS/filedesc WITNESS report
remains undiagnosed. Exercise lock stress, waiter interruption, shared-memory
mapping/truncation/removal and MAC checks on a completed test kernel; measure
resource usage and latency rather than inferring performance from compilation.

### Sleepqueue and turnstile objects (2026-10-28)

Native objects retain configured instrumentation and allocated runtime sections
relative to Make, with profiling/stack/scheduler option headers compared byte
for byte. Runtime wait/wake, signal interruption, priority propagation and
contention measurement remain required; object parity cannot diagnose the
open lock-order report or establish latency. No probe or synchronization
source behavior changed during conversion.

### Deferred work kernel objects (2026-10-28)

Preserved seven taskqueue, eight group-taskqueue and four epoch probe
definitions; allocated SDT sections and runtime relocations match Make.
Runtime checks must cover enqueue/run/cancel/drain and epoch callbacks under
concurrency and teardown, along with real probe delivery and resource usage.
No source instrumentation or scheduling/reclamation behavior changed.

### Timer and callout objects (2026-10-28)

Native objects preserve configured instrumentation, allocated data and runtime
relocations relative to Make. Live clock selection/adjustment, callout callback
lifecycle and timer delivery still need tests; collect timing and contention
measurements under load. Object parity does not establish clock accuracy or
latency. No source timing or instrumentation behavior was altered.

### Kqueue built-in object (2026-10-28)

`sys/kern/kern_event.c` has 16 SDT probe definitions covering queue creation,
close, registration, attachment/drop, process attachment, scan/wait/copyout
and drain/detach. Native GENERIC output matches Make allocated sections and
runtime relocations, including probe metadata; raw CTF and symbols also
match. Evidence: `/usr/obj/usr/src/bazel-events-kernel-20261028/qualification`.
No source instrumentation was changed. Live probe firing, event semantics
and audit coverage remain runtime/integration qualification; compilation
parity alone does not establish those properties.

### Pipe/socket built-in objects (2026-10-28)

sys_pipe.c, uipc_socket.c and uipc_sockbuf.c contain respectively 17, 15 and
2 SDT probe definitions. Native GENERIC objects match Make symbols, raw CTF,
allocated sections and runtime relocations, including SDT metadata. Evidence:
`/usr/obj/usr/src/bazel-sockets-kernel-20261028/qualification`. Existing MAC
calls remain unchanged; live enforcement and probe firing are unqualified.
Audit coverage across socket syscalls and descriptor passing requires the
syscall-layer/integration review; object parity does not establish coverage.

### UNIX-domain sockets and socket syscalls (2026-10-28)

uipc_usrreq.c has 20 SDT probe definitions, including SCM_RIGHTS transfer,
transfer denial/consumption, local-socket lifecycle and garbage collection.
uipc_syscalls.c has existing AUDIT_ARG_SOCKET/FD/SOCKADDR calls and MAC checks
for create/bind/listen/accept/connect/send/receive/setsockopt. It has no local
SDT_PROBE_DEFINE declarations; lower socket layers carry probes. No missing
probe requirement is inferred solely from that absence.

Both native GENERIC objects match Make symbols, raw CTF, allocated sections
and runtime relocations, including existing instrumentation. Evidence:
`/usr/obj/usr/src/bazel-unix-sockets-kernel-20261028/qualification`.
Live descriptor-transfer denials, audit records, probes and policy outcomes
remain to be exercised; source/object inspection is not runtime proof.

### Descriptor management and general I/O (2026-10-28)

kern_descrip.c contains ten SDT probe definitions for advisory locking,
descriptor install/dup/close, fork inheritance and exec/fork flag enforcement
and consumption. sys_generic.c has audit arguments and MAC ioctl checks,
but no local SDT_PROBE_DEFINE declarations. Both native GENERIC objects match
Make symbols, raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-descriptor-io-kernel-20261028/qualification`.

Source-review follow-ups (not changed by this build conversion):
- kern_fcntl currently calls AUDIT_ARG_FD(cmd), followed by AUDIT_ARG_CMD(cmd),
  despite having a separate fd parameter. Review descriptor attribution and
  exercise emitted audit records before claiming correct fcntl audit coverage.
- kern_dup retains an XXXRW comment for recording the destination descriptor
  with AUDIT_ARG_FD2. Review against current mode/flags semantics and audit
  event encoding; do not mechanically activate the historical comment.
- The recorded filedesc/ZFS lock-order reversal remains open. Compilation
  parity does not establish safe close/kqueue/vnode locking under contention.

Live probe firing, audit records and policy enforcement remain unqualified.

### Capsicum and process descriptors (2026-10-28)

sys_capability.c contains 36 SDT probe definitions; sys_procdesc.c contains
four. Existing instrumentation covers rights/mode/transfer operations and
process-descriptor open/transfer; both sources have audit argument calls.
Native GENERIC objects match Make symbols, raw CTF, allocated sections and
runtime relocations, including probe metadata. Evidence:
`/usr/obj/usr/src/bazel-capsicum-procdesc-kernel-20261028/qualification`.
No source instrumentation or policy checks were changed. Live rights denial,
transfer, process lifecycle, audit output and probe firing remain unqualified.

### Fork and exit handling (2026-10-28)

kern_fork.c defines the proc:create SDT probe; kern_exit.c defines proc:exit
and two proclife exit-status/reap probes. Existing KDTRACE_HOOKS paths and
audit argument calls remain unchanged. Native GENERIC objects match Make
symbols, raw CTF, allocated sections and runtime relocations, including probe
metadata. Evidence:
`/usr/obj/usr/src/bazel-process-lifecycle-kernel-20261028/qualification`.

Follow-up: kern_exit.c retains comments questioning the wait idtype/id audit
arguments; consecutive AUDIT_ARG_VALUE(idtype) and AUDIT_ARG_VALUE(options)
also merit checking against actual audit event encoding. Review emitted
records for each wait identifier type before claiming coverage. No audit
semantics were changed in this build conversion. Live process probes, audit
records, inheritance and teardown races remain unqualified.

### Signals and credentials (2026-10-28)

kern_sig.c defines proc signal-send/clear/discard probes; kern_prot.c defines
credential UID/GID and setid-exec probes. Existing audit arguments record
signal and credential operations. Native GENERIC objects match Make symbols,
raw CTF, allocated sections and runtime relocations, preserving existing
instrumentation. Evidence:
`/usr/obj/usr/src/bazel-signal-credentials-kernel-20261028/qualification`.
No policy or instrumentation source was changed. Live signal-denial behavior,
credential transitions, MAC decisions, audit records and probe firing remain
unqualified; compile parity alone does not establish end-to-end coverage.

### Executable loading (2026-10-28)

kern_exec.c defines proc exec/exec-failure/exec-success SDT probes, includes
KDTRACE/HWPMC/HWT hooks and records argv/environment/vnode/fd audit arguments.
Native GENERIC output matches Make symbols, raw CTF, allocated sections and
runtime relocations, including instrumentation. Evidence:
`/usr/obj/usr/src/bazel-exec-kernel-20261028/qualification`.
Generated hook options match Make; no instrumentation was disabled or runtime
source changed. Live successful/failed exec, tracing hooks, audit records and
policy enforcement remain unqualified.

### Thread management (2026-10-28)

kern_thread.c defines proc:lwp-exit; kern_thr.c has signal/process audit
arguments and hardware tracing/performance-counter hook paths. Native GENERIC
objects match Make symbols, raw CTF, allocated sections and runtime
relocations. All generated tracing/WITNESS options match Make. Evidence:
`/usr/obj/usr/src/bazel-threads-kernel-20261028/qualification`.
No hooks were disabled and no runtime source changed. Thread lifecycle,
audit records, hook firing and contention remain runtime qualification;
absence of local SDT definitions in kern_thr.c alone is not a coverage verdict.

### User-mutex synchronization (2026-10-28)

kern_umtx.c defines four SDT probes for wake, sleep-start, sleep-done and
priority-inheritance ownership. Native GENERIC output matches Make symbols,
raw CTF, allocated sections and runtime relocations, including probe metadata.
Evidence: `/usr/obj/usr/src/bazel-umtx-kernel-20261028/qualification`.
No source instrumentation changed. No AUDIT_ARG calls were found locally;
that alone does not establish a missing audit requirement for synchronization
operations. Live contention, ownership transitions, probes and MAC outcomes
remain unqualified.

### Resource limits and process accounting (2026-10-28)

kern_resource.c defines four procresource nice/limit start/done probes;
kern_acct.c defines acct:config and retains mac_system_check_acct calls.
Native GENERIC objects match Make symbols, raw CTF, allocated sections and
runtime relocations, including probe metadata. Evidence:
`/usr/obj/usr/src/bazel-resource-accounting-kernel-20261028/qualification`.
No runtime source changed. No local AUDIT_ARG calls were found in either
source; review syscall event mapping and emitted argument records for
setrlimit/setpriority/acct before claiming complete audit coverage. Local
absence alone is not proof that syscall auditing is absent. Live probes,
accounting records and permission enforcement remain unqualified.

### Privilege checks, login classes and identity (2026-10-28)

kern_priv.c defines three privilege success/error/credential-error probes;
its MAC integration remains unchanged. kern_loginclass.c and kern_mib.c have
no local SDT_PROBE_DEFINE or AUDIT_ARG calls. Review login-class transition
observability with syscall event mapping and resource accounting before
claiming complete coverage; local absence alone is not an auditing verdict.
All three native GENERIC objects match Make symbols, raw CTF, allocated
sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-identity-privilege-kernel-20261028/qualification`.
Live policy decisions, audit records and probe firing remain unqualified.

### RACCT and RCTL (2026-10-28)

kern_racct.c defines accounting/lifecycle/throttle probes; kern_rctl.c defines
three enforcement probes for deny, signal and throttle. Native GENERIC objects
match Make symbols, raw CTF, allocated sections and runtime relocations.
Evidence: `/usr/obj/usr/src/bazel-resource-control-kernel-r2-20261028/qualification`.
No instrumentation source changed. No local AUDIT_ARG calls were found;
review rule-management syscall audit mapping and emitted records before
claiming administrative-operation coverage. Live resource enforcement,
accounting accuracy and probe firing remain unqualified.

### CPU affinity and scheduling helpers (2026-10-28)

kern_cpuset.c defines affinity set-start/set-done probes. kern_switch.c and
ksched.c have no local SDT_PROBE_DEFINE or AUDIT_ARG calls; scheduler-level
instrumentation requires separate sched_ule review. Native GENERIC objects
match Make symbols, raw CTF, allocated sections and runtime relocations.
Evidence: `/usr/obj/usr/src/bazel-affinity-scheduling-kernel-20261028/qualification`.
No instrumentation source changed. Review administrative affinity/scheduling
syscall audit mapping and records before claiming coverage. Live probes,
permission decisions and scheduling behavior remain unqualified.

### ULE scheduler (2026-10-28)

sched_ule.c calls shared sched probes for load, priority changes/lending,
on/off/remain-CPU, surrender and enqueue/dequeue, and retains HWPMC/HWT and
KDTRACE hook paths. Absence of local SDT_PROBE_DEFINE declarations does not
mean these calls lack instrumentation. Native GENERIC output matches Make
symbols, raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-ule-kernel-20261028/qualification`.
All generated hook/scheduler option headers match Make. No runtime source
changed. Shared provider linkage and live firing, context-switch hooks and
scheduler behavior remain linked-kernel qualification.

### Synchronization and SMP coordination (2026-10-28)

kern_synch.c defines the sched:preempt probe and has KTR sleep/switch call sites.
subr_smp.c has KTR signal-forwarding and CPU stop/restart call sites. Native
GENERIC output matches Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-synch-smp-kernel-20261028/qualification`.
No instrumentation source changed. This qualifies only the selected GENERIC
configuration, not arbitrary KTR configurations. Live probes, cross-CPU
coordination and sleep/wakeup behavior remain unqualified.

### Sysctl handling (2026-10-28)

kern_sysctl.c defines the sysctl:write probe and retains MAC/Capsicum checks.
Native GENERIC output matches Make symbols, raw CTF, allocated sections and
runtime relocations, including probe metadata. Evidence:
`/usr/obj/usr/src/bazel-sysctl-kernel-20261028/qualification`.
No instrumentation source changed. No local AUDIT_ARG calls were found;
review sysctl syscall event mapping and emitted records before claiming
administrative-write audit coverage. Live permissions, probe firing and
concurrent sysctl lifecycle behavior remain unqualified.

### Kernel environment and event handlers (2026-10-28)

kern_environment.c defines kenv set/unset probes and retains MAC checks.
subr_eventhandler.c has KTR_EVH list/item lifecycle call sites. Native GENERIC
objects match Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-environment-events-kernel-20261028/qualification`.
No instrumentation source changed; arbitrary KTR variants were not tested.
Review kenv syscall audit mapping and emitted records before claiming
administrative-write coverage. Live probes, permissions and handler lifecycle
concurrency remain unqualified.

### Kernel module/linker management (2026-10-28)

kern_linker.c defines load-deny/load/unload probes and retains MAC and hardware
tracing/performance-counter paths. kern_module.c has no local SDT_PROBE_DEFINE
or AUDIT_ARG calls. Native GENERIC objects match Make symbols, raw CTF,
allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-module-linker-kernel-20261028/qualification`.
No source instrumentation changed. Review module syscall audit mapping and
emitted records before claiming administrative coverage. Live registration,
load/unload, policy decisions and probe firing remain unqualified; no host
module loading was performed.

### Kernel ELF loader backends (2026-10-28)

link_elf.c and link_elf_obj.c retain mac_kld_check_load calls. No local SDT
probe or AUDIT_ARG calls were found; the previously reviewed kern_linker layer
provides load/deny/unload probes. Native GENERIC objects match Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-elf-loaders-kernel-20261028/qualification`.
No instrumentation source changed. Live backend errors, caller-level probes,
audit coverage and policy denial remain unqualified; no host modules loaded.

### Kernel object dispatch and preload metadata (2026-10-28)

subr_kobj.c and subr_module.c have no local SDT/AUDIT call sites. Object lookup
statistics are conditional on KOBJ_STATS; that variant was not qualified.
Absence of probes does not itself establish an instrumentation requirement
for internal method lookup or preload metadata. Native GENERIC objects match
Make symbols, raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-kobj-preload-kernel-20261028/qualification`.
No runtime source changed. Live dispatch and boot preload behavior remain
unqualified.

### Kernel startup (2026-10-28)

init_main.c retains BOOTTRACE SYSINIT/startup call sites and KDTRACE_HOOKS
initialization paths. Native GENERIC output matches Make symbols, raw CTF,
allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-init-kernel-20261028/qualification`.
No startup or instrumentation source changed. This is compile evidence only;
boot trace collection, SYSINIT ordering and PID 1 operation remain unqualified.

### Clock handling (2026-10-28)

kern_clock.c defines/calls sched:tick; kern_clocksource.c has KTR clock-event,
interrupt and idle/active call sites. Native GENERIC objects match Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-clocks-kernel-20261028/qualification`.
No tracing source changed. Arbitrary KTR configurations and live tick/probe
firing, clock accuracy and interrupt overhead remain unqualified.

### Event timers and timer descriptors (2026-10-28)

sys_timerfd.c defines 14 SDT probes for allocation, configuration, expiration,
read/wait and close; creation records clock/flags audit arguments. kern_et.c
has no local SDT/AUDIT calls. Native GENERIC objects match Make symbols, raw
CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-event-timers-kernel-20261028/qualification`.
No instrumentation source changed. Live timer delivery, audit records and
probe firing remain unqualified; creation arguments alone do not establish
complete audit coverage of timer operations.

### Eventfd and inotify (2026-10-28)

sys_eventfd.c defines 14 SDT probes and records creation flags for audit;
vfs_inotify.c defines five probes covering wait, watch add/remove and queueing.
Native GENERIC objects match Make symbols, raw CTF, allocated sections and
runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-notifications-kernel-20261028/qualification`.
No instrumentation source changed. Inotify audit mapping and records require
review before claiming coverage; local probes alone are not audit records.
Live delivery, permissions, probe firing and lifecycle races remain unqualified.

### Kernel threads and POSIX scheduling (2026-10-28)

kern_kthread.c retains TSTHREAD timestamp logging; p1003_1b.c retains scheduling
policy privilege checks. No local SDT/AUDIT calls were found in these sources
or posix4_mib.c. Review scheduling syscall audit mapping and records before
claiming coverage; lower scheduler layers provide separate probes. Native
GENERIC objects match Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-kthread-posix-kernel-20261028/qualification`.
No runtime source changed. Live thread lifecycle, policy decisions and logging
remain unqualified.

### Getrandom and UUID generation (2026-10-28)

sys_getrandom.c and kern_uuid.c have no local SDT/AUDIT calls. Review syscall
mapping and provider-level observability before deciding whether additional
instrumentation is needed; randomness payloads should not be logged. Native
GENERIC objects match Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-random-uuid-kernel-20261028/qualification`.
No runtime source changed. Entropy quality/provider behavior and live syscall
semantics are not established by compilation parity.

### Kernel logging and message buffers (2026-10-28)

subr_log.c and subr_msgbuf.c have no local SDT/AUDIT calls. They implement
logging transport/storage, so absent probes do not establish missing audit
coverage. Native GENERIC objects match Make symbols, raw CTF, allocated
sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-logging-kernel-20261028/qualification`.
No source instrumentation changed. End-to-end delivery to normal logging
services, buffer wraparound and reader lifecycle remain unqualified.

### Kernel formatted output and sbuf (2026-10-28)

subr_prf.c and subr_sbuf.c have no local SDT/AUDIT calls. These formatting
primitives underpin logging; their lack of probes alone is not a coverage
failure. Native GENERIC objects match Make symbols, raw CTF, allocated
sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-formatted-output-kernel-20261028/qualification`.
No runtime source changed. Console delivery, sbuf drain/error handling and
concurrent logging remain unqualified.

### UIO helpers and range locking (2026-10-28)

subr_uio.c and kern_rangelock.c have no local SDT/AUDIT call sites. Review
higher-level I/O observability and contention measurements before deciding
whether low-level probes are needed. Native GENERIC objects match Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-uio-rangelock-kernel-20261028/qualification`.
No runtime source changed. Copy-fault handling, contention and filesystem
performance remain unqualified.

### SMR and pctrie helpers (2026-10-28)

subr_smr.c and subr_pctrie.c have no local SDT/AUDIT call sites. Review existing
counters/debugger facilities and reclamation/lookup measurements before
adding low-level instrumentation. Native GENERIC objects match Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-smr-pctrie-kernel-20261028/qualification`.
No runtime source changed. Concurrency, reclamation and resource behavior
remain unqualified.

### Counters and blist (2026-10-28)

Neither source has local SDT/AUDIT calls. Counters themselves support system
observability; internal allocator operations do not automatically need audit
records. Native GENERIC objects match Make symbols, raw CTF, allocated sections
and runtime relocations after correcting the machine-header __FILE__ mapping.
Evidence: `/usr/obj/usr/src/bazel-counter-blist-kernel-r2-20261028/qualification`.
Initial diagnostic-string/relocation mismatch is retained in the initial run.
Concurrent counter and allocator behavior remain unqualified.

### Hash tables and identifier allocation (2026-10-28)

subr_hash.c and subr_unit.c have no local SDT/AUDIT call sites. Internal
allocation/lookup primitives do not automatically require audit records;
review caller-level observability and contention measurements as needed.
Native GENERIC objects match Make symbols, raw CTF, allocated sections and
runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-hash-unit-kernel-20261028/qualification`.
No runtime source changed. Concurrent lookup and identifier lifetime behavior
remain unqualified.

### ACL helpers and VFS ACL entry points (2026-10-28)

vfs_acl.c defines six probes for get/check/set/remove and has type/vnode/fd
audit arguments. subr_acl_nfs4.c has no local SDT/AUDIT calls; higher VFS
layers provide instrumentation. Native GENERIC objects match Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-acl-kernel-20261028/qualification`.
No runtime source changed. Live ACL/MAC decisions, inheritance, audit records
and probe firing remain unqualified. The unselected ufs_acl/POSIX.1e variant
is not covered by this evidence.

### VFS extended attributes (2026-10-28)

vfs_extattr.c defines six get/list/set/remove probes and records command,
namespace, attribute-name and descriptor audit arguments. Native GENERIC
output matches Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-extattr-kernel-20261028/qualification`.
No runtime source changed. Live namespace/MAC decisions, audit records,
filesystem persistence and probe firing remain unqualified.

### VFS pathname lookup (2026-10-28)

vfs_lookup.c defines lookup entry/return probes and records directory-fd,
user-path and vnode audit arguments. Native GENERIC output matches Make
symbols, raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-lookup-kernel-20261028/qualification`.
No runtime source changed. Live path resolution, security boundaries, audit
records and probe firing remain unqualified.

### VFS name cache (2026-10-28)

vfs_cache.c has 23 SDT probe definitions. Native GENERIC output matches Make
symbols, raw CTF, allocated sections and runtime relocations, preserving probe
metadata. Evidence:
`/usr/obj/usr/src/bazel-namecache-kernel-20261028/qualification`.
No runtime source changed. No local AUDIT_ARG calls were found; assess cached
lookup auditing with the surrounding namei/syscall paths rather than inferring
coverage from includes. Live probes, cache invalidation, permissions and
concurrent filesystem behavior remain unqualified.

### VFS vnode operations (2026-10-28)

vfs_vnops.c retains seven AUDIT_ARG_VNODE1 sites and conditional HWPMC/HWT
mmap hooks. No local SDT probe definitions were found; vnode interface probes
are generated separately and need end-to-end coverage with their callers.
Native GENERIC output matches Make symbols, raw CTF, allocated sections and
runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-vnops-kernel-r4-20261028/qualification`.
No runtime source changed. Actual audit records, mmap hook delivery and
filesystem behavior remain unqualified.

### VFS defaults, hashing and initialization (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in vfs_default.c,
vfs_hash.c or vfs_init.c. Generated vnode interface probes and surrounding
syscall audit paths must be assessed together; absence of local calls does
not establish missing coverage. Native GENERIC output matches Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-vfs-defaults-kernel-20261028/qualification`.
No runtime source changed. Live probe/audit coverage, fallback dispatch and
concurrent vnode lifecycle behavior remain unqualified.

### VFS mount and root mount (2026-10-28)

vfs_mount.c retains four mount SDT probe definitions and audit calls for flags,
filesystem type and filesystem identifier. vfs_mountroot.c has no local SDT
or AUDIT_ARG calls; early boot coverage must be assessed in its boot context.
Native GENERIC output matches Make symbols, raw CTF, allocated sections and
runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-mount-kernel-20261028/qualification`.
No runtime source changed. Probe delivery, audit records, mount authorization,
root discovery and concurrent unmount remain unqualified. The recorded
ZFS/filedesc WITNESS issue remains open and is not resolved by object parity.

### VFS system calls (2026-10-28)

vfs_syscalls.c retains four SDT probe definitions (copy range start/done,
chflags and chroot) and its existing AUDIT_ARG calls for descriptors, vnodes,
flags, ownership, modes and other syscall arguments. Native GENERIC output
matches Make symbols, raw CTF, allocated sections and runtime relocations.
Evidence: `/usr/obj/usr/src/bazel-vfs-syscalls-kernel-20261028/qualification`.
No runtime source changed. This does not prove complete audit argument coverage
or live probe firing; syscall records, authorization and error paths need
linked-kernel tests.

### VFS vnode lifecycle (2026-10-28)

vfs_subr.c retains four SDT probe definitions for syncer start/done and detach
start/done. No local AUDIT_ARG calls were found; audit coverage must be assessed
at the surrounding syscall layer. Native GENERIC output matches Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-vfs-lifecycle-kernel-20261028/qualification`.
No runtime source changed. Live probes, vnode reclamation, syncer behavior and
concurrent lifecycle operations remain unqualified.

### Buffered and clustered VFS I/O (2026-10-28)

vfs_bio.c retains nine buffer-cache SDT probe definitions for reclamation,
space waits, flushes, write waits and I/O completion. No local SDT definitions
were found in vfs_cluster.c and neither source has local AUDIT_ARG calls;
assess surrounding vnode/syscall coverage before proposing additional probes.
Native GENERIC output matches Make symbols, raw CTF, allocated sections and
runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-vfs-buffer-io-kernel-20261028/qualification`.
No runtime source changed. Probe delivery, pressure/error paths and CPU,
memory and disk I/O performance remain unqualified.

### Asynchronous VFS I/O (2026-10-28)

vfs_aio.c retains 26 SDT probe definitions spanning submit, queue, scheduling,
completion, cancellation, reaping, limits, process rundown, fsync and list I/O.
No local AUDIT_ARG calls were found; syscall audit integration must be assessed
with event mappings and surrounding entry points. Native GENERIC output
matches Make symbols, raw CTF, allocated sections and runtime relocations.
Evidence: `/usr/obj/usr/src/bazel-vfs-aio-kernel-20261028/qualification`.
No runtime source changed. Probe delivery, asynchronous ordering, cancellation,
resource limits and runtime performance remain unqualified.

### VFS exports (2026-10-28)

vfs_export.c retains eight nfsexport SDT probe definitions covering export
configuration, address lists, default exports, mapped credentials, grants and
lookups. No local AUDIT_ARG calls were found; assess mount syscall audit
records and service-level policy together. Native GENERIC output matches Make
symbols, raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-vfs-export-kernel-r2-20261028/qualification`.
No runtime source changed. Live NFS authorization, mapped identities, probes
and policy update concurrency remain unqualified.

### File locking (2026-10-28)

kern_lockf.c retains seven SDT probe definitions for wait start/done,
cancellation, conflicts, deadlock, grant and wake. No local AUDIT_ARG calls
were found; assess fcntl/flock syscall auditing separately. Native GENERIC
output matches Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-file-locks-kernel-20261028/qualification`.
No runtime source changed. Live probes, lock contention, deadlock detection,
owner cleanup and lock performance remain unqualified.

### Memory descriptors and scatter/gather lists (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in subr_memdesc.c or
subr_sglist.c. These helpers serve lower-level memory and I/O consumers;
assess caller instrumentation before introducing hot-path probes. Native
GENERIC output matches Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-memory-descriptors-kernel-20261028/qualification`.
No runtime source changed. Driver integration, boundary/error handling and
runtime CPU/memory/I/O performance remain unqualified.

### x86 bus DMA (2026-10-28)

The x86 bounce implementation includes subr_busdma_bounce.c, retaining four
busdma SDT definitions for reserve failure, deferral, readiness and callbacks.
The included source is a declared textual dependency. Native GENERIC output
matches Make symbols, raw CTF, allocated sections and runtime relocations.
Evidence: `/usr/obj/usr/src/bazel-busdma-kernel-20261028/qualification`.
No runtime source changed. Live DMA behavior, probe delivery, callback races,
IOMMU integration and performance remain unqualified.

### Device statistics and resource manager (2026-10-28)

subr_devstat.c retains the io provider start/done probes. No local SDT
or AUDIT_ARG calls were found in subr_rman.c; assess resource consumers and
existing debugger/sysctl visibility before proposing instrumentation.
Native GENERIC output matches Make symbols, raw CTF, allocated sections and
runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-device-resources-kernel-20261028/qualification`.
No runtime source changed. Live I/O probes, accounting accuracy and resource
allocation behavior remain unqualified.

### Disk helpers and range sets (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in subr_disk.c or
subr_rangeset.c. Assess GEOM/device/syscall callers for observability before
adding probes to these helpers. Native GENERIC output matches Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-disk-ranges-kernel-20261028/qualification`.
No runtime source changed. Live disk control, range-boundary/error behavior
and runtime performance remain unqualified.

### Buffer rings and mutex pools (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in subr_bufring.c or
kern_mtxpool.c. Assess callers and shared locking instrumentation before
adding hot-path probes. Native GENERIC output matches Make symbols, raw CTF,
allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-buffer-mutex-pools-kernel-20261028/qualification`.
No runtime source changed. Live concurrency, lifetime/error paths and
contention performance remain unqualified.

### Helper hooks and object storage (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in kern_hhook.c,
kern_khelp.c or kern_osd.c. These framework callbacks are not themselves
DTrace probes; assess consumers, module lifecycle and jail paths for coverage.
Native GENERIC output matches Make symbols, raw CTF, allocated sections and
runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-helper-hooks-kernel-20261028/qualification`.
No runtime source changed. Live callback/lifetime behavior, teardown races
and performance remain unqualified.

### Device hints and firmware loading (2026-10-28)

subr_firmware.c retains seven SDT probe definitions for load waits, lookup,
module loading and binary loading. No local SDT or AUDIT_ARG calls were found
in subr_hints.c; assess device configuration callers for coverage. Native
GENERIC output matches Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-hints-firmware-kernel-20261028/qualification`.
No runtime source changed. Live firmware probes, missing-image/privilege
errors, loading concurrency and hardware integration remain unqualified.

### Device-control notifications (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in kern_devctl.c.
Assess device-event consumers and bus lifecycle instrumentation together;
event delivery itself does not prove trace or audit coverage. Native GENERIC
output matches Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-devctl-kernel-20261028/qualification`.
No runtime source changed. Live notifications, reader/wakeup races, privilege
checks and queue-pressure behavior remain unqualified.

### Bus framework (2026-10-28)

subr_bus.c retains four newbus SDT definitions around driver attach/detach
callbacks. Early boot callbacks precede probe enablement, so runtime coverage
must distinguish boot from later device operations. Native GENERIC output
matches Make symbols, raw CTF, allocated sections and runtime relocations.
Evidence: `/usr/obj/usr/src/bazel-bus-kernel-20261028/qualification`.
No runtime source changed. Live driver callbacks, failure paths, suspend/resume,
IOMMU integration and device-management concurrency remain unqualified.

### Device initialization and common DMA (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in subr_autoconf.c
or subr_bus_dma.c. Assess deferred initialization diagnostics and driver/
architecture DMA probes together before adding instrumentation. Native GENERIC
output matches Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-device-init-dma-kernel-20261028/qualification`.
No runtime source changed. Live ordering, DMA mappings, callback/error paths
and performance remain unqualified.

### Physical I/O dispatch (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in kern_physio.c.
Assess device/GEOM I/O probes and surrounding read/write audit paths together
before adding instrumentation. Native GENERIC output matches Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-physio-kernel-20261028/qualification`.
No runtime source changed. Live mapping/transfer/error behavior and runtime
CPU/memory/disk performance remain unqualified.

### Character-device lifecycle (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in kern_conf.c.
Assess driver/devfs lifecycle probes and device syscall audit paths together
before proposing instrumentation. Native GENERIC output matches Make symbols,
raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-character-devices-kernel-20261028/qualification`.
No runtime source changed. Live creation/destruction, reference races and
private-data cleanup remain unqualified.

### Clock and FAT timestamp conversion (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in subr_clock.c or
subr_fattime.c. Assess clock/filesystem consumers before adding instrumentation
to conversion helpers. Native GENERIC output matches Make symbols, raw CTF,
allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-clock-conversion-kernel-20261028/qualification`.
No runtime source changed. Calendar/range/precision behavior and driver clock
integration remain unqualified; special clock calibration compilation is pending.

### Clock calibration (2026-10-28)

subr_clockcalib.c retains TSENTER/TSEXIT boot timing hooks and existing
calibration diagnostics. No local SDT definitions or AUDIT_ARG calls were
found; early boot timing is the relevant instrumentation context. Native
GENERIC output with the special -O3/MMX/SSE/SSE2 settings matches Make
symbols, raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-clock-calibration-kernel-20261028/qualification`.
No runtime source changed. Actual calibration, clock wrap/failure paths and
boot timing remain unqualified.

### Real-time clock management (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in subr_rtc.c.
Assess clock drivers, diagnostics and time-setting syscall audit paths
together before adding instrumentation. Native GENERIC output matches Make
symbols, raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-rtc-kernel-20261028/qualification`.
No runtime source changed. Live hardware clock access, invalid values and
synchronization behavior remain unqualified.

### NTP and feed-forward clock support (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in kern_ntptime.c or
kern_ffclock.c. Assess time-setting syscall audit mappings and existing clock
status diagnostics together. Native GENERIC output matches Make symbols, raw
CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-clock-discipline-kernel-20261028/qualification`.
GENERIC has PPS_SYNC enabled and FFCLOCK disabled; the enabled FFCLOCK branch
is unqualified. No runtime source changed. Live adjustment/privilege paths,
PPS behavior and clock stability remain unqualified.

### CPU idle and memory barriers (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in kern_idle.c or
kern_membarrier.c. Assess scheduler/architecture probes and syscall audit
mappings together before adding hot-path instrumentation. Native GENERIC
output matches Make symbols, raw CTF, allocated sections and runtime
relocations. Evidence:
`/usr/obj/usr/src/bazel-idle-membarrier-kernel-20261028/qualification`.
No runtime source changed. Live SMP ordering, idle transitions and runtime
performance remain unqualified.

### CPU frequency and per-CPU storage (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in kern_cpu.c or
subr_pcpu.c. Assess frequency driver callbacks, sysctl access and allocator
instrumentation together before adding probes. Native GENERIC output matches
Make symbols, raw CTF, allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-cpu-frequency-storage-kernel-20261028/qualification`.
No runtime source changed. Live frequency transitions, per-CPU lifetime,
concurrency and performance remain unqualified.

### Thread contexts and shared pages (2026-10-28)

No local SDT definitions or AUDIT_ARG calls were found in kern_context.c or
kern_sharedpage.c. Assess syscall/signal and VM instrumentation together
before adding probes. Native GENERIC output matches Make symbols, raw CTF,
allocated sections and runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-context-sharedpage-kernel-20261028/qualification`.
No runtime source changed. Live context restoration, signal masks, user-pointer
errors and shared-page/VDSO behavior remain unqualified.

### Process control (2026-10-28)

kern_procctl.c retains 26 procctl SDT definitions covering commands, denials,
process security controls and reaper operations. No local AUDIT_ARG calls
were found; syscall event/argument audit mappings require separate review.
Native GENERIC output matches Make symbols, raw CTF, allocated sections and
runtime relocations. Evidence:
`/usr/obj/usr/src/bazel-process-control-kernel-20261028/qualification`.
No runtime source changed. Live probes, authorization, inheritance, reaper
races and audit records remain unqualified.

### Process metadata and enumeration (2026-10-28)

kern_proc.c retains the proc SDT provider and KDTRACE_HOOKS lifecycle handling.
No local SDT probe definitions or AUDIT_ARG calls were found; assess proc
provider consumers and syscall/sysctl auditing together. Native output matches
Make symbols, raw CTF, allocated sections and relocations. Evidence:
`/usr/obj/usr/src/bazel-process-metadata-kernel-20261028/qualification`.
Live provider behavior, metadata visibility and lifecycle races remain unqualified.

### beep (2026-10-28)

Native beep preserves the existing source, including capability-mode entry.
This conversion adds no application probes or audit calls. Audio device and
syscall instrumentation must be assessed with the driver stack. Eight safe
argument/error cases match Make; actual playback and capability-mode device
setup remain unqualified. Evidence:
`/usr/obj/usr/src/bazel-beep-20261028/qualification/parity.json`.


### 2026-10-28: bintrans

Native conversion carries bintrans.c, uuencode.c, uudecode.c and qp.c unchanged.
No local SDT/DTrace/AUDIT hooks found in those sources. This does not establish
missing syscall auditing; encoding/decoding uses ordinary file/stdio paths.
No new probes or audit policy added. Direct fixture and alias behavior compares
with Make; ATF startup remains blocked by the recorded capability-rights ABI
assertion, and legacy TAP Bazel runtime integration remains pending.


### 2026-10-28: at

at, panic, parsetime and perm sources contain no local SDT/DTrace/AUDIT hooks;
conversion leaves them unchanged. Scheduling and privilege transitions deserve
an installed-system audit check together with atrun/PAM: early invalid-input
comparisons do not exercise those paths. No inference that syscall audit hooks
are absent, and no new probes or audit policy introduced in this conversion.


### 2026-10-28: atrun

atrun/gloadavg contain no local SDT/DTrace/AUDIT hooks. PAM and login capability
paths stay enabled and link existing native libraries with their configured
DTrace inputs. Runtime source is unchanged. VM checks must cover PAM account
and session handling, credential changes, queued/batch job execution and syslog;
compile/link/manual parity and cache reuse do not qualify those behaviors.


### 2026-10-28: chat and comsat

Neither source has local SDT/DTrace/AUDIT hooks; native conversion preserves
sources unchanged. chat tty/modem exchanges, timeouts and syslog, and comsat
mail notification/terminal writes deserve integration coverage. Early invocation
checks do not exercise them. No claim that syscall auditing is absent; no probe
or audit-policy changes introduced.


### 2026-10-28: c89 and c99

No local SDT/DTrace/AUDIT hooks in either unchanged compiler frontend. Process
exec auditing, where applicable, belongs to the existing exec path; absence of
local hooks does not establish missing syscall audit coverage. Argument and
language-mode qualification uses host cc and does not test live audit events.


### 2026-10-28: killall

Preserves signalall operation-start and operation-done probes via native DTrace
rules. Two probe schemas match Make and both ordinary/is-enabled instruction
sites pass offline validation. Configured-disabled build omits DOF. No live
firing, signal delivery or jail semantics qualified; runtime comparisons only
list signals and show help. No runtime sources or audit policy modified.


### 2026-10-28: lessecho

No local SDT/DTrace/AUDIT hooks in lessecho/version sources. Shared less sources
and configuration remain unchanged. Quoting/error behavior compares with Make;
no new tracing or audit policy is introduced and no live audit check is claimed.


### 2026-10-28: ctlstat

No local SDT/DTrace/AUDIT hooks in unchanged ctlstat source. CTL ioctl and
statistics collection paths need installed-VM coverage, including JSON and
Prometheus modes; early option checks do not exercise those paths. No claim
that syscall auditing is absent and no new probes/audit policy introduced.


### 2026-10-28: finger

No local SDT/DTrace/AUDIT hooks found in the five unchanged source files.
User/session lookup, config aliases and remote queries still need integration
coverage; invalid-option parity does not cover them. No new probes or audit
policy; absence of local hooks does not establish missing syscall auditing.


### 2026-10-28: fingerd

No local SDT/DTrace/AUDIT hooks in unchanged source. Optional blocklist success
and denial reports remain configured with MK_BLOCKLIST_SUPPORT's Bazel counterpart;
verify their live behavior with an isolated service. Both artifact variants match
Make; debug protocol checks cover only disabled reporting. Syslog, inetd/TCP and
real-client execution remain runtime gates. No new probe or audit policy added.


### 2026-10-28: leave

No local SDT/DTrace/AUDIT hooks in unchanged source. Capsicum setup preserved;
both Make and native binaries abort at the recorded capability-rights assertion
on current host/SDK startup. Timer and terminal behaviors remain unqualified.
No security bypass, probes or audit policy added to get a runtime pass.


### 2026-10-28: ipcrm

Shared ipc.c contains ipcsnapshot wrappers, but ipcrm's maintained Make recipe
does not enable WITH_COVERAGE_DTRACE; native compilation preserves that behavior.
ipcrm.c has no local SDT/DTrace/AUDIT hooks. Review whether destructive IPC
operations warrant explicit probes/audit coverage independently of conversion;
no claim that syscall audit hooks are absent. Private ID-removal tests pass for
all three IPC classes; key/global/jail and kernel-memory paths remain open.


### 2026-10-28: ldd

No local SDT/DTrace/AUDIT hooks in unchanged ldd source. Runtime-loader paths and
O_VERIFY input open behavior are preserved. Known-ELF dependency reporting
compares with Make on the current loader; this does not qualify live loader or
exec audit events, arbitrary architectures or a newly built installed image.


### 2026-10-28: lock

No local SDT/DTrace/AUDIT hooks in unchanged lock source; native PAM keeps its
configured library instrumentation. Private temporary-key PTY checks pass, but
PAM authentication, syslog events, setuid transitions and console locking remain
installed-system coverage. No new probes/audit policy or authentication bypass.


### 2026-10-28: login

Preserves login auth/fail DTrace probes and optional BSM login_audit compilation.
Full-feature probe schemas and ordinary instruction sites match Make offline;
disabled-feature build omits DOF/BSM as configured. Live PAM authentication,
credential transitions, terminal/session setup, BSM event emission and provider
registration still require VM qualification. No bypass or runtime source change.

### 2026-10-28: chpass

No direct SDT/DTrace, BSM audit or syslog calls found in local chpass sources.
Native build preserves sources and crypt/util dependencies, with optional
ypclnt. Account-change audit coverage is a follow-up across chpass, libutil
password database operations and installed kernel audit configuration; no new
hooks or runtime bypass added. NIS-enabled artifact qualification remains
blocked by missing SDK/world NIS inputs; non-NIS artifact parity is not live
account-change or audit-event qualification.

### 2026-10-28: libc YP object group

No direct SDT/DTrace, BSM audit or syslog hooks found in xdryp.c/yplib.c.
Preserves maintained sources and libc namespace/private interfaces. Generated
RPC schema code and six object variants have offline comparison evidence only;
NIS network, cache, timeout and identity-lookup behavior remain runtime coverage.
No new instrumentation, network calls or credentials were exercised here.

### 2026-10-28: libc XDR object group

No direct SDT/DTrace, BSM audit or syslog hooks found in the eight XDR sources.
Preserves libc namespace handling and RPC private interfaces. All ordinary/PIC
objects have offline symbol and text comparison evidence; malformed-stream,
record I/O, allocation-failure and live RPC behavior require runtime coverage.
Existing NetBSD XDR tests are identified but not yet integrated or executed here.

### 2026-10-28: existing XDR runtime case

Unchanged NetBSD double/enumeration encode/decode case now passes as a Bazel ATF
test linked to native XDR PIC objects. Native symbol ownership and Make fixture
bytes verified separately. This adds serialization runtime evidence only; it
does not cover transport events, kernel audit, live RPC services or full libc.

### 2026-10-28: librpcsvc

No direct SDT/DTrace, BSM audit or syslog hooks found in handwritten librpcsvc
sources. Native build carries those sources and generated RPC XDR schemas
unchanged. Artifact comparison covers the NIS-disabled variant, not network
calls, key handling, service authentication or live audit behavior. NIS variant
and installed-system runtime qualification remain open.

### 2026-10-28: maintained RPC suite

Native-built installed-program variants preserve both NetBSD RPC test programs.
Local raw RPC and XDR cases passed with checked native ATF/librpcsvc/libutil and
SDK libc/libsys. This exercises SDK libc's RPC implementation; it is not proof
of a native complete libc. Six network/service cases remain explicit unrun
qualification work. No test source edits or root/service requirement bypasses.

### 2026-10-28: libc RPC implementation

Carries all 58 configured RPC sources and crypt RPC generation. Existing syslog
error paths in transport/configuration handling remain unchanged. No direct
SDT/DTrace/BSM audit hooks found in the RPC C sources; no new hooks introduced.
116 ordinary/PIC objects have symbol/text parity, not live network, key-service,
NSS-cache, syslog-emission or audit-event qualification. Complete native libc
linkage and service/runtime tests remain necessary.

### 2026-10-28: libc nameser and ISC groups

No direct SDT/DTrace, BSM audit or syslog calls found in the six nameser and two
ISC C sources. All 16 ordinary/PIC objects have symbol/text parity evidence.
Resolver name-resolution probes remain in the separate resolv sources, which
are not yet converted here. Live DNS, event scheduling, resolver probes and
installed libc behavior remain runtime qualification work.

### 2026-10-28: libc resolver objects

Preserves resolver query/server start/done hooks and enabled checks, generated
from the unchanged libc nameres_provider.d shared with NSS/semaphore providers.
Raw res_send objects retain the DOF archive anchor and eight probe/enabled
references; generated header and 28 object variants match Make offline. Final
combined libc DOF rewriting, retention, registered provider sites and live DNS
probe/audit behavior are still unqualified. No probe disabling or partial-provider
substitution was used to make the build pass.

### 2026-10-28: libc inet object group

No direct SDT/DTrace, BSM audit or syslog hooks found in the 14 inet C sources.
Native objects preserve maintained implementations; 28 ordinary/PIC variants
have symbol/text parity evidence. Address-parser runtime tests, malformed input
coverage and complete libc qualification remain open. No new probes or audit
policy introduced.

### 2026-10-28: inet parser runtime cases

Four unchanged NetBSD basic/error cases pass against native inet_addr/inet_ntoa
and inet_network definitions. Saved-binary symbol checks establish native routine
ownership; SDK libc remains for other functions. No live networking, audit events,
new probes or full libc/system runtime qualification is implied.

### 2026-10-28: libc network/NSS objects

Retains nsdispatch's configured name-resolution probe references and shared libc
DOF anchor in ordinary/PIC objects. Maintained syslog/error handling and generated
NSS parser behavior remain unchanged. 82 objects have symbol/text comparison;
parser generation differences are confined to verified #line paths. No live NSS,
cache daemon, NIS/Hesiod, kernel/network or audit-event behavior is qualified.
Final shared libc provider processing and registration remain open.

### 2026-10-28: libc configuration staging

Native staging preserves all libc network/NSS/RPC/account/MAC configuration and
reuses existing pwd_mkdb generation. Make metadata and bytes match with NIS on
and off (fresh staging only). Generated account files remain untagged state.
No host account mutation, MAC policy installation, live authentication/NSS or
audit event behavior was exercised; those remain installed-system tests.

### 2026-10-28: libc ACL/MAC object group

Carries the maintained ACL, extended-attribute and MAC interfaces unchanged,
including the userland mode of the shared NFSv4 ACL implementation. The word
"audit" in ACL text parsing is an ACE type, not a newly added audit hook. No
direct SDT/DTrace/BSM hook was found in these local C sources. Object comparison
does not establish kernel audit emission, mac_abac/openES behavior, permission
enforcement or live filesystem ACL compatibility; runtime qualification remains.

## 2026-10-28: libc database routines

Reviewed the 31 database compilation sources (btree, dispatch, hash/ndbm,
mpool and recno). No direct DTrace/SDT or BSM audit calls were found in this
source group. Existing diagnostics remain unchanged. Database-level probes
could improve latency/error visibility, but require a deliberate API/provider
design; the migration adds none. Security auditing belongs also at callers
that modify accounts or policy; this object comparison does not qualify those
callers or establish runtime audit coverage. Ordinary/PIC .text and symbol
parity evidence: bazel-libc-db-build-20261028/qualification/parity.json.

## 2026-10-28: libc gdtoa conversion routines

Reviewed libc gdtoa wrappers and imported netlib sources. No direct DTrace/SDT
or BSM audit calls were found. The migration preserves source behavior and adds
no hot-path probes. Conversion edge-case runtime tests remain necessary at libc
integration; object parity alone does not establish numeric API correctness.
Evidence: bazel-libc-gdtoa-build-20261028/qualification/parity.json (42 objects).

## 2026-10-28: libc stdio

Reviewed the 111 maintained stdio sources. No direct DTrace/SDT or BSM audit
calls were found; native targets retain existing locking/cancellation and error
paths. Adding probes to frequently called stream functions would require a
separate cost/semantics review. No probes were invented during migration.
Object parity (222 ordinary/PIC objects) is recorded in
bazel-libc-stdio-build-20261028-r2/qualification/parity.json. Runtime concurrency,
EINTR and stream behavior still require the maintained stdio test suite.

## 2026-10-28: libc locale

Reviewed locale sources, including the iconv-enabled and disabled C16/C32 paths.
No direct DTrace/SDT or BSM audit calls were found. Existing diagnostics remain;
no conversion-loop probes were introduced. This is not proof of locale-data or
Citrus module loading behavior, nor of runtime audit coverage. Both configured
ordinary/PIC object sets match Make; evidence is in
bazel-libc-locale-{yes,no}-build-20261028-r2/qualification/parity.json.

## 2026-10-28: libc iconv/Citrus

Reviewed regular Citrus/iconv sources and static wrappers. No direct DTrace/SDT
or BSM audit calls were found. Existing secure_getenv(PATH_I18NMODULE), default
module path selection and libc_dlopen behavior remain unchanged. Module loading
and encoding database use require runtime qualification; matching object code
does not prove either. No probe or auditing policy changes were added.
Evidence: bazel-libc-iconv-build-20261028/qualification/parity.json (55 objects).

## 2026-10-28: libc_nonshared

The shared wrapper inventory retains the iconv forwarding functions and empty
stub without new runtime code or probes. The iconv source audit applies; native
hidden symbol visibility is compared explicitly to Make for all 12 members.
No complete libc link or runtime module-loading claim follows from the archive
and metadata checks. Evidence: bazel-libc-nonshared-build-20261028-r3/qualification.

## 2026-10-28: libc stdtime/tzcode

Reviewed time routines and imported timezone code; no direct DTrace/SDT or BSM
audit calls found. Existing time conversion, locking and optional timezone-change
detection code remain unchanged. Both option values match maintained Make object
code. Source time32.c retains its documented temporal-locality/post-2038 TODO;
this migration neither repairs nor proves those semantics. Runtime reload and
edge-case testing remains necessary with a complete native libc and zone data.
Evidence: bazel-libc-{stdtime,stdtime-detect}-build-20261028/qualification.

## 2026-10-28: libc regex

Reviewed regcomp, regerror, regexec, regfree and textually included engine.c.
No direct DTrace/SDT or BSM audit calls were found. No probes were added to
matching loops. libc's collation path remains enabled and must be exercised by
runtime tests with locale data; standalone libregex evidence is not a substitute.
Object evidence: bazel-libc-regex-build-20261028/qualification/parity.json.

## 2026-10-28: non-allocator libc stdlib

Reviewed the maintained non-allocator stdlib sources. No direct DTrace/SDT or
BSM audit calls found. Native targets preserve cancellation, destructor, exit,
secure environment and sorting paths without new probes or policy. Lifecycle
and thread tests remain necessary at aggregate libc qualification; .text and
symbol parity alone do not prove those behaviors. Allocator observability is
outside this source group's coverage. Evidence: bazel-libc-stdlib-build-20261028/
qualification/parity.json (148 ordinary/PIC objects).

## 2026-10-28: jemalloc

Maintained platform headers enable JEMALLOC_UTRACE; jemalloc.c retains its
UTRACE_CALL hook through the platform preamble. Native targets consume those
headers unchanged. Matching undefined symbols and .text in both malloc modes
preserve the compiled paths, but no live ktrace/utrace execution or allocator
performance is claimed. Debug assertions remain in debug archives and absent
from production archives. Evidence: bazel-libc-jemalloc{,-production}-build-20261028/
qualification/parity.json and production qualification/modes.json.

## 2026-10-28: sized-free wrappers

Both wrappers forward to __free and retain weak aliases without direct probes or
audit hooks. Native object parity and the maintained sized_deallocation ATF case
pass. The test links native wrappers and SDK allocator, so runtime jemalloc utrace
behavior is not established. Evidence: bazel-libc-sized-free-test-20261028-r2,
including qualification/link-proof.json and the saved ATF report.

## 2026-10-28: libc UUID

No direct DTrace/SDT or BSM audit calls found in the nine UUID sources. Creation
uses uuidgen; kernel syscall auditing is separate from this userland group.
Existing uuid_create sets success status and ignores uuidgen's return value;
error-path behavior deserves separate runtime review and is not changed during
migration. Object parity does not establish generation success or uniqueness.
Evidence: bazel-libc-uuid-build-20261028/qualification/parity.json (18 objects).

## 2026-10-28: libc message catalogs

No direct DTrace/SDT or BSM audit calls found in msgcat.c. Existing NLSPATH access
uses secure_getenv and remains unchanged. Matching objects do not establish
runtime catalog search, privilege filtering or concurrent cache behavior; those
remain complete-libc tests. Evidence: bazel-libc-msgcat-build-20261028/qualification.

## 2026-10-28: compat-43, secure and stdbit

No direct DTrace/SDT or BSM audit calls found in the migrated groups. The existing
stack-protector failure path logs LOG_CRIT through syslog and raises SIGABRT;
object parity preserves it but does not establish delivery to logging services.
Legacy signal/identity operations delegate to existing interfaces; kernel audit
coverage is separate. No hooks or policy were changed. Runtime fortify/signal
and bit-operation tests remain open. Evidence: bazel-libc-smallgroups-build-20261028-r2.

## 2026-10-28: gmon, libc startup and x86 context

No direct DTrace/SDT or BSM audit hooks found in these groups. gmon retains its
profil-based sampling and mcount bookkeeping; getcontextx retains CPUID and
sysarch extended-state handling. Object parity does not verify profiling output,
startup relocation or CPU-state capture. No hooks or runtime behavior changed.
Evidence: bazel-libc-startup-build-20261028/qualification.

## 2026-10-28: libc C system wrappers

No direct DTrace/SDT or BSM audit calls found in the 61 migrated C wrappers,
including shared ptrace/recvmmsg/sendmmsg sources. Interposition, cancellation and
kernel syscall observation must be checked in their owning layers; object parity
alone does not establish audit coverage or runtime thread semantics. No hooks or
policy changes were added. Evidence: bazel-libc-syswrappers-build-20261028-r2/
qualification/parity.json (122 ordinary/PIC objects).

## 2026-10-28: libc static/shared libsys variants

No direct DTrace/SDT or BSM audit calls found in auxv.c, interposing_table.c or
libc_stubs.c. Native groups preserve auxiliary-vector access, interposition table
and intentional shared trap stub. Runtime filter resolution and thread dispatch
still require full-library tests. Evidence: bazel-libc-libsysvariants-build-20261028/
qualification/parity.json. No hooks or runtime source changes introduced.

## 2026-10-28: common libc/libsys C sources

No direct DTrace/SDT or BSM audit calls found in the eight common sources migrated
in libc mode. Time-interface vDSO and syscall paths, errno and page-size helpers
remain unchanged. Kernel observation and actual fast-path use require runtime
qualification. Evidence: bazel-libc-libsyscommon-build-20261028/qualification/parity.json.

## 2026-10-28: amd64 libc/libsys support

No direct DTrace/SDT or BSM audit hooks found in the ten migrated C/assembly
sources. Existing sysarch/syscall and error paths remain unchanged. Kernel syscall
observation is separate; text and relocation parity do not prove runtime tracing
or CPU-state correctness. Evidence: bazel-libc-libsysamd64-build-20261028/qualification.

## 2026-10-28: x86 libc timecounter, PKRU and CPU-number support

No direct DTrace/SDT or BSM audit hooks found in these three sources. Existing
clock fallback, Hyper-V and CPU-feature selection code remains unchanged.
Object parity for both Hyper-V settings does not establish actual fast-path use,
latency or runtime observation. Evidence: bazel-libc-libsysx86-{yes,no}-build-20261028/
qualification/parity.json. No instrumentation added to timing-sensitive paths.

## 2026-10-28: libc string and wide-character routines

No direct DTrace/SDT or BSM audit hooks found in the migrated string/amd64-string
sources or explicit_bzero. No instrumentation added to these hot paths.
Optimized and portable object comparisons preserve the selected implementation,
including timing-safe and explicit-zero routines, but do not establish timing,
zeroization at runtime, IFUNC selection or memory-boundary behavior. Maintained
string tests (including timing-safe, memcpy and locale cases) still need native
runtime integration; object parity does not replace those tests.

## 2026-10-28: amd64 libc general routines

No direct SDT/DTrace or BSM audit hooks found in the 16 migrated sources.
Jump/context and floating-point paths retain their existing behavior; no new
instrumentation added. Object parity is not runtime signal-state, FP-control or
tracing evidence. Six maintained makecontext argument/return cases pass with
native makecontext and SDK context syscalls; setjmp/sigsetjmp and maintained
fpsetmask/fpsetround tests still need native runtime integration.

## 2026-10-28: libc directory/traversal/glob group

No direct SDT/DTrace or BSM audit hooks found in the 23 migrated sources.
Existing filesystem syscalls retain their kernel observation paths; that is not
proof of runtime audit delivery. Seven maintained directory tests pass using
native open/read/close/seek/tell routines with SDK support. Native fts/glob,
Blocks, Capsicum, compatibility ABI and concurrent traversal tests remain open.
No new instrumentation was added to traversal loops.

## 2026-10-28: libc process, signal and time helpers

No direct SDT/DTrace or BSM audit hooks found in these 42 migrated sources.
Process creation, exec and signal syscalls retain their existing kernel paths;
object parity does not prove audit-event delivery or runtime process behavior.
Ten native signal conversion/set-operation cases pass; no real signal delivery
or process-launch runtime qualification is claimed. The posix_spawn comparison
caught incorrect broad -fexceptions use; corrected for this group, with a
cross-component libc flag/exception-section audit now required before linking.

## 2026-10-28: non-cancellation libc exception-flag correction

Removed broad -fexceptions from 31 libc BUILD files after confirming Make's
final per-source cancellation restriction. Requalification covers 1,694 objects
including raw exception/unwind section contents, and 24 passing ATF cases.
This is not active unwinding, DTrace registration or BSM event-delivery evidence.
No provider definitions or source instrumentation changed. Alternate configuration
qualification and future cancellation-point handling remain explicit requirements.

## 2026-10-28: alternate exception-flag configurations

Renewed six alternate component configurations after removing broad libc
-fexceptions. All 594 object and raw exception-section comparisons match Make.
No new runtime tracing or cancellation claims. Future sem_new.c migration must
declare semwait_trace.h and the shared nameres provider header, preserve the
SEMWAIT park/wake probes and static anchor, and include those contributors in
the complete libc provider link. libthr/librt broad exception flags are deliberate;
their separately named no-unwind options remain future qualification work.

## 2026-10-28: semaphore cancellation group

sem_new.c's existing SEMWAIT park/wake start/done references and nameres static
anchor are preserved in the native group. Declared semwait_trace.h/provider
header dependencies are conditional on DTrace. All four DTrace/unwind mode
combinations match Make objects and exception sections; action arguments and
raw probe reference presence are also checked. sem.c has no direct probes.
Active provider registration, concurrent wait/wake/cancellation behavior and
latency still require complete libc linking and runtime qualification.

## 2026-10-28: random-number and entropy routines

No direct SDT/DTrace or BSM audit hooks found in the migrated random/entropy
sources. No instrumentation of generated random values or entropy material was
added. getentropy's existing syscall path is preserved and three native cases
pass; runtime audit delivery is not established. arc4random private _elf_aux_info
linkage requires native libc/libsys integration before its maintained fork and
uniform-bound tests can run. Repeated reseed, concurrency, fallback and latency
qualification remain open; object parity is not cryptographic validation.

## 2026-10-28: libc system/path/terminal helper group

No direct SDT/DTrace or BSM audit hooks found in these 57 migrated sources.
Existing syslog/diagnostic behavior and syscall observation paths are retained;
object/exception-section parity does not establish runtime event delivery.
wordexp's maintained shell builtin, syslog socket recovery and terminal/service
interaction require later runtime qualification. crypt.c contains pre-existing
legacy compatibility stubs; no cryptographic behavior or new instrumentation
is asserted by its native compilation.

## 2026-10-28: libc general support group

No direct SDT/DTrace or BSM audit hooks found in the 26 migrated sources.
Existing thread interposition and extended-error paths are unchanged. Native
object/exception-section parity does not qualify runtime thread initialization,
login-record writes or event delivery. Static pututxline testing and full native
libc/libthr runtime integration remain required. Existing stub functions are
part of libc's maintained design, not migration workarounds.

## 2026-10-28: libc loader interfaces and imported utilities

No direct SDT/DTrace or BSM audit hooks found in these seven migrated sources.
Existing weak loader-service stubs, TLS bootstrap interfaces and imported
utility implementations are unchanged. Object/exception-section parity does not
prove loader interposition, TLS lifetime, tracing or lookup-cache behavior.
Full native loader/libc runtime qualification remains required.

## 2026-10-28: libc account and group lookup routines

No direct SDT/DTrace or BSM audit hooks found in these five sources. Existing NSS
routing and cache interaction remain source-identical; lower-level NSS provider
probes belong to the separate net group and eventual combined libc DOF link.
Three configuration comparisons pass, but authentication, account-policy effects,
NIS/Hesiod service behavior, NSS cache recovery and concurrent lookup runtime
coverage remain outstanding. No host account/group or NSS configuration changed.

## 2026-10-28: libc capability-rights helper

No direct SDT/DTrace or BSM audit hooks found in subr_capability.c. Its maintained
userspace implementation is compiled directly; no new policy or instrumentation
added. Ordinary/PIC object and exception-section parity does not establish kernel
rights enforcement or runtime auditing. Existing capsicum tests and full native
libc/kernel integration remain necessary for those claims.

## 2026-10-28: generated syscall inventory

The native Bazel symbol list is generated with syscall.mk's existing ABI filter;
all 452 native inventory entries match. Existing eight generated outputs remain
byte-identical, including tracing argument generation. No new probes, syscall
wrappers or policy changes are introduced in this producer change. Assembly and
runtime audit/tracing behavior remain to be qualified with the native consumers.

## 2026-10-28: native generated amd64 syscall assembly

450 generated stubs preserve Make's PSEUDO/interposed/handwritten exclusions,
compatibility symbol versions and stack notes. Static libc gets full syscall
bodies; shared libc gets the existing empty filtered bodies. All 900 objects
match text, global/undefined symbols and text relocations against fresh Make.
No tracing or audit policy changed. Syscall entry auditing and DTrace syscall
providers belong to kernel/runtime qualification, which this object comparison
does not establish. Complete native libc/libsys links and runtime tests remain.

## 2026-10-28: native libsys complete amd64 source groups

477 sources/954 ordinary and PIC objects preserve Make's text, symbols and text
relocations, with identical ABI map. libsys exposes audit syscalls; this does not
mean it owns kernel audit policy. No new SDT providers or audit logging are added.
The direct syscall smoke test covers successful pipe I/O and EBADF, not audit
records, DTrace syscall probes, thread errno, IFUNC timekeeping or shared-library
interposition. Those remain full runtime/kernel qualification obligations.

## 2026-10-28: compiler-rt builtins and shared libsys

Native compiler-rt preserves the 165 configured amd64 builtin implementations;
no probes or audit policy were added. Arithmetic/conversion tests prove a bounded
runtime subset. Static and shared direct syscall tests pass; the latter loads
verified native libsys.so.7. ABI and linker-property parity does not qualify
thread-local errno selection, IFUNC timekeeping, audit records, syscall tracing,
atomic contention or full compiler-generated arithmetic. Those broader runtime
checks remain outstanding. A caught whole-archive linkage error was fixed in the
dependency graph, retaining shared runtime test coverage against recurrence.

## 2026-10-28: compiler-rt/libsys installation and debug artifacts

Installation preserves the qualified native archives and exposes libsys's split
DWARF companion through a verified GNU debug-link CRC. Headers/manual payloads and
links match Make in default and split-manpage modes. This supports later debugging
and tracing workflows but does not itself establish DTrace probe behavior, live
symbolication, audit records or full debugger/runtime correctness. No runtime
instrumentation or security policy was changed by these installation targets.

## 2026-10-28: whole-libc DTrace composition and runtime smoke checks

Native libc combines resolver/NSS/semaphore probe objects into one provider per
ordinary/PIC variant. Linked shared libc and the static smoke executable contain
12 schemas, 14 ordinary sites and 15 enabled sites; the maintained DOF validator
checks function ranges and patched NOP/RET/XOR instructions. Shared schema/site
counts match Make, and constructor/destructor ordering preserves DOF init/fini.
Actual registration and live probe firing are not established by these checks.
The existing allocation, text, stream, mapping, fork/pipe and numeric-resolution
smoke checks pass with native libraries, but do not replace libc runtime suites,
audit-record tests, thread/cancellation checks or performance qualification.

## 2026-10-28: full-runtime libc ATF selection

33 maintained ATF cases now run against complete native libc/libsys instead of
embedding selected libc objects. Loader and imported-symbol checks cover all ten
programs. Added the existing arc4random fork/uniform cases after full native auxv
became available. Passing these cases does not establish live DTrace firing,
audit-record coverage, entropy strength, thread cancellation or all libc features.
No instrumentation or audit policy was altered for this test integration.

## 2026-10-28 libc shared public interface

Native libc shared consumers now have an explicit interface including nonshared
public wrappers. Link qualification covers iconv_open/iconv_close/iconvctl; their
existing maintained test is not run until conversion modules/data are declared.
No probes or audit hooks were removed or added. The shared smoke program now
links native libc directly; two static/shared smoke cases passed. Live DTrace
and audit behavior remain outside this evidence. See checkpoint link-interface
section and bazel-libc-link-interface-20261028-r3 qualification report.

## 2026-10-28 Citrus modules

All 23 lib/libiconv_modules targets preserve their maintained C sources, including
shared mapper_serial/mapper_parallel implementation. Source scan found no existing
DTRACE/SDT_PROBE or audit_ calls in these modules. No hooks were removed. These
conversion libraries do not themselves establish a new authentication/audit
boundary; do not invent probes merely to satisfy migration coverage. Runtime
loader provenance is covered by 23 passing native Bazel tests; conversion data,
full conversion semantics, installation and performance remain to qualify.

## 2026-10-28 mkesdb and mkcsmapper

Native lexer/parser generation preserves the maintained .l/.y sources and their
error handling. Source scan found no existing DTRACE/SDT_PROBE or audit_ hooks in
these utilities; none were removed. They produce conversion databases rather
than establish a new authentication boundary. Byte parity covers all 656 binary
databases produced by the maintained i18n build with native static tools versus
fresh Make generators. Native data actions, installation and full iconv runtime
remain outstanding; this is generator qualification, not service auditing.

## 2026-10-28 native character-map data actions

415 per-source CitrusDatabase actions expose their generator, source and output
to Bazel execution records. This moves data generation into the dependency graph;
it does not introduce runtime probes or change conversion code. Initial execution
configuration build produced approximately 2 GiB of JSON action diagnostics;
record this as build diagnostic-storage overhead for full-system performance
qualification. Broader conversion/runtime and installation remain incomplete.

## 2026-10-28 encoding data generation

237 native database actions and 182 template outputs preserve the maintained
conversion inputs; all match Make's complete output inventory and bytes. Big5's
six variable-driven actions explicitly record the template, variable table,
script and native awk dependency. No conversion C code, probes or audit hooks
were changed. Alias/index generation, installation and end-to-end conversion
remain necessary before declaring the iconv runtime qualified.

## 2026-10-28 encoding indexes

Native index actions declare all maintained encoding alias files and generate
both text inventories before compiling their databases. Bazel analysis rejects
index membership inconsistent with generated encoding databases. All four text
and binary outputs match Make. No runtime probes or audit hooks were changed;
mapper indexes, installation and full conversion tests are still outstanding.

## 2026-10-28 mapper indexes

Native mapper directory/pivot generation declares family metadata and every
maintained source fragment. Both text and binary index outputs match Make,
including KOI parallel and ISO-8859 GR/zone/serial mappings. No runtime C code,
DTrace probes or audit hooks changed. All 656 generated binary i18n files now have
native generation/parity evidence; installation and full iconv runtime remain
unqualified. Generation evidence must not be reported as conversion testing.

## 2026-10-28 i18n installation

The complete native i18n installation archive now matches Make for all 687 file
payloads/metadata and 35 component directory records. This includes static ISO646
maps, not only generated binary databases. No runtime code, probes or audit hooks
changed. This establishes installation coverage for share/i18n only; dynamic
module installation, end-to-end conversion and package publication remain.

## 2026-10-28 installed Citrus modules

All 23 stripped installed modules retain their previously qualified .text bytes,
pass separate-debug CRC checks and load with native runtime libraries. Metadata
matches Make for 72 unique file/link/directory records. No conversion source,
DTrace or audit hooks changed. Existing loader tests now also qualify installation
copies; this remains module loading evidence, not end-to-end character conversion.

## 2026-10-28 native iconv CLI and prepared runtime qualification

The existing CLI source is unchanged; its native libc/nonshared link interface
is now explicit. The complete native data/module fixture and maintained
privilege-dropping chroot checker are prepared. Runtime checks are pending host
root assistance because unprivileged chroot is disabled. No new probes, host
policy exceptions or path redirection were added to conversion code. Linkage
checks must not be reported as completed conversion tests.

## 2026-10-28 installed database generators

Both stripped installed generator programs preserve their native .text, retain
valid separate debug links and reproduce all 656 database outputs with native
libc/libsys. Manuals and full component installation metadata match Make. No
runtime source, DTrace probes or audit hooks changed. This is generator execution
evidence; it does not substitute for the pending isolated iconv conversion run.

## 2026-10-28 installed libc observability preservation

The native stripped libc installation artifact retains byte-identical .text and
.SUNW_dof sections from the previously qualified full libc. Its separate debug
CRC/name and DWARF-info presence pass; the existing smoke probe runs using that
installed library copy and native libsys. No probes or audit hooks were removed.
Live DTrace provider registration/firing and full system runtime are not established
by section preservation. Library payload metadata matches Make; documentation,
catalog/config coverage and broader tests remain separate work.

## 2026-10-28 libc catalogs and gencat

All 27 libc catalog bytes and 28 directory records match the maintained Make
installation. Catalog generation now declares a static native-libc execution
tool. NLS-disabled qualification produces no catalogs and runs no catalog action.
No conversion/catalog C sources, DTrace probes or audit hooks changed; changes
are link dependencies and package directory metadata. Catalog lookup behavior and
normal installed gencat runtime remain outside this evidence.

## 2026-10-28 libc manuals and aliases

All 459 maintained libc manual sources and 972 aliases now have native declared
installation paths; default and iconv-disabled/split-package variants match Make
bytes, metadata and hardlink inode relationships. This is documentation coverage,
not evidence of runtime probe or audit behavior. No runtime sources or hooks were
changed. Canonical alias-chain handling preserves the existing Make relationships.

## 2026-10-28 aggregate libc installation

The combined package payload preserves the four previously qualified native
library/debug binaries byte-for-byte, including the existing DTrace-bearing
library. All package-tagged installation records match maintained Make in the
qualified amd64 configuration. No runtime sources, probes or audit hooks change.
Generated account databases remain separate initial state; neither account
migration nor authentication behavior is demonstrated by this archive check.

## 2026-10-28 libc NOSSP variant

All 1442 NOSSP member executable sections match the maintained Make archive;
the ordinary PIC archive remains byte-identical to its earlier qualification.
DTrace-transformed libc objects use the NOSSP configuration, while drti keeps
its separately built compiler policy. An initially overbroad transition was
rejected by symbol comparison and replaced with a libc-only setting. No C
sources, probes or audit hooks changed. This does not establish live DTrace
registration/firing or qualify the still-unbuilt native runtime linker.

## 2026-10-28 runtime-linker core

Native rtld preserves its maintained lazy DTrace provider and patched core
object code. All 12 core executable-section payloads and normalized global/
undefined symbols match Make. The provider has DOF and probe-site relocations
without libc-dependent runtime imports or constructor sections. With dtrace
disabled, all 12 core objects still match Make and no DTrace generation action
runs. This is compilation/provider evidence; final loader linkage and live
probe firing remain unqualified. No audit or signature-check source changed.

## 2026-10-28 runtime-linker replacement libc

All 42 replacement-libc objects match independent Make executable sections and
global/undefined symbols. The core, replacement code and provider inventories
reconcile to all 55 Make compilation outputs. Private rtld namespace headers
and generic string implementations are retained. No runtime C sources, DTrace
probes or audit hooks changed; final loader runtime remains unqualified.

## 2026-10-28 selected runtime-linker dependencies

The six libc NOSSP and 32 libsys PIC objects selected for rtld match Make's
explicit inventory, executable-section bytes and global/undefined symbols.
Selection forwards declared compiler outputs without pulling in transitive
library objects. No C source, DTrace provider or audit hook changed. Final
loader dependency checks and runtime observability remain pending linkage.

## 2026-10-28 linked native runtime loader

Native rtld links with the lazy provider and matches Make's ten DTrace schemas.
Twelve ordinary and fourteen enabled sites pass instruction-byte validation;
there are no constructor dependencies. The disabled variant has no DOF. Both
loaders execute the native-libc smoke program with confirmed native libc/libsys
selection. Live probe registration/firing and broad loader runtime behavior are
not established. Link-map rejection gates preserve Make's dependency isolation;
no signature verification, audit or runtime C source was changed.

## 2026-10-28 installed runtime-loader payload

Stripping rtld preserves byte-identical native .text and .SUNW_dof sections.
Its separate debug filename/CRC and DWARF presence pass. The stripped artifact
executes a native-libc smoke probe with explicit native libc/libsys selection.
No runtime sources, probes or audit hooks changed. This does not establish
live DTrace firing, full installation or the broader loader runtime suite.

## 2026-10-28 explicit-loader ATF execution

Two maintained rtld ATF cases pass under the declared native loader with native
libc/libsys/private ATF provenance. Test C sources are unchanged. The adapter
records explicit-loader selection and preserves body/cleanup result handling;
19 protocol/lifecycle regressions pass. No runtime probes or audit hooks changed.
This does not qualify child exec interpreter selection or live DTrace firing.

## 2026-10-28 runtime-linker deep binding

The maintained deep-binding ATF case passes under native rtld with independently
verified fixture dependency separation and $ORIGIN behavior matching Make.
Original C sources and assertions remain unchanged. Native loader/runtime
provenance is recorded; no audit or DTrace hooks changed. This single case
does not establish general loader behavior or live probe firing.

## 2026-10-28 native libthr loading cases

Two existing dlopen ATF cases pass through native rtld with native libthr.
Process-local name traces confirm the declared fixture lookup, with no host
libthr lookup. Original C sources and checks are unchanged. Handle-close
behavior and the recursion regression are covered; thread creation, TLS and
physical library unmapping are not established. No probes/audit hooks changed.

## 2026-10-28 rtld integer and signature-verifier cases

Two unchanged maintained ATF cases now pass through native rtld. Parser
extraction equals Make's output. Signature classification and syscall transport
are injected by the original test; real cryptographic checks and kernel
transport are not established by this evidence. No DTrace or audit hooks were
added, removed or modified. Existing rtld probe qualification remains separate;
live probe firing and broader runtime coverage remain open.

## 2026-10-28 descriptor-loading fixture builds

Both maintained descriptor-test programs and their child now build with Bazel.
Four ELF dependency/interpreter/search-path layouts match independent Make
references. No test source, fexecve behavior, DTrace probe or audit hook changed.
These are compilation/link checks only. The eleven ATF runtime cases remain
unqualified against native rtld until an isolated installed runtime is used.

## 2026-10-28 top-level rtld test packaging

Seven test executables now have native installation/debug manifests and their
maintained Kyua index. Twenty metadata records match rootless Make installation;
all seven debug-link/CRC/DWARF pairs validate. This is packaging evidence only,
with helper/deepbind installation still separate and no new runtime cases.
No production code, DTrace probes or audit hooks changed.

## 2026-10-28 descriptor helper installation

The target child and complete libpythagoras installation now join the test
archive. Twenty-six records match Make; nine debug pairs validate. The static
archive contains the correct ordinary object with matching code and symbols.
No production or test C source, audit hooks or DTrace probes changed. This does
not add runtime qualification for the pending descriptor cases.

## 2026-10-28 complete rtld tests installation

Deepbind's three DSOs, program, links, debug files and nested Kyua index now
complete the maintained rtld test-directory archive. Forty metadata records
match Make and thirteen debug pairs validate. The existing deepbind_simple case
passes again from stripped archive payloads under native rtld, preserving the
$ORIGIN fixture layout. No C source, DTrace probes or audit hooks changed.
Descriptor child-exec coverage and live probe firing remain separate gates.

## 2026-10-28 configured rtld test inclusion

The existing tests setting now controls inclusion of the complete loader test
suite in the rtld install archive. Disabled output is byte-identical to the
qualified loader-only archive; enabled output matches the qualified 49-record
union. One shared source-owned inventory serves both archive targets. No probe,
audit hook, runtime source or test semantics changed. No new runtime passes.

## 2026-10-28 getty

Converted all four maintained getty translation units without changing C source.
No dedicated DTrace/SDT or audit calls were found in these units. Existing syslog
configuration, terminal and login-exec diagnostics remain compiled. Getty hands
off to login; absence of direct audit calls here does not establish an audit
failure, nor does linking libutil prove its probes fired. Record PTY/serial
startup, chat failures, login handoff and corresponding login/PAM audit events
for integrated runtime qualification; consider dedicated terminal-state probes
only after that review. Build/metadata/symbol parity passed; no getty process was
started on a host terminal.

## 2026-10-28 revnetgroup and phttpget

Native conversion preserves all existing C sources and diagnostics. Build,
installation and four bounded runtime comparisons match Make. No dedicated
DTrace or audit integration was introduced; mapping generation and HTTP request
lifecycle/error visibility remain review candidates, not migration completion
criteria proven by symbol parity. HTTP network behavior has not been exercised.
libulog/ulog-helper conversion remains open; its login-record side effects
require separate qualification without writing host accounting databases.

## 2026-10-28 libulog and ulog-helper build graph

All maintained library/helper sources remain unchanged. libulog writes utmpx
records through pututxline and forks/execs the installed helper for pseudo-terminal
recording. No dedicated DTrace or direct audit calls were found in the converted
library units. ABI and six ordinary/PIC object comparisons match Make; this does
not prove accounting updates or authorization behavior. Isolated tests must
cover PTY ownership, login/logout records, helper failures and relevant audit
policy without writing host accounting data. Setuid installation metadata and
runtime qualification are still pending.

## 2026-10-28 libulog/helper installation

The installation graph now preserves headers, compatibility aliases, manuals,
debug data and helper setuid metadata. Twenty-three records match Make; no
library/helper source, probes or audit hooks changed. Metadata qualification
does not establish helper authorization or utmpx accounting behavior. Isolated
PTY and login/logout tests remain pending; the helper was not executed and host
accounting state was not modified.

## 2026-10-28 rpc.sprayd and rpc.rquotad

Native build conversion preserves the daemon sources and explicit generated RPC
protocol interfaces. Existing syslog registration, reply and argument failures
remain compiled. No dedicated DTrace/direct audit calls were found in these
daemon units. Runtime review must cover inetd versus standalone startup,
registration cleanup, malformed requests, AUTH_UNIX rejection and ordinary/
extended quota replies. Symbol/header/install parity does not establish these
behaviors or audit coverage. No daemon was started on the host.

## 2026-10-28 tcpd

Native conversion preserves tcpd.c, its syslog severity/facility definitions
and host-access policy delegation to libwrap. Default and IPv6-disabled build/
install comparisons match Make. No probe/audit hooks were added or removed.
Record isolated allow/deny, hostname/ident failure, IPv4/IPv6 and daemon-exec
checks with syslog/audit review for runtime qualification. Compile-time option
parity does not establish policy behavior; no wrapper/service was executed.

## 2026-10-28 rbootd

All six existing source units are compiled unchanged; object code and symbols
match Make. Existing syslog allocation, request, unknown-packet and connection
messages remain present. No dedicated DTrace or direct audit hooks were found
in these units. Isolated BPF/interface startup, reload, client authorization,
boot/read/error responses and their log visibility remain runtime review items.
Build parity is not evidence of packet handling or audit correctness. The daemon
was not executed and no BPF device or network listener was opened.

## 2026-10-28 TFTP client/server

The shared file/I/O/options/transfer/utils sources are explicitly declared for
both native programs without source changes. Existing logging and wrapper-policy
behavior is retained by compilation; no new audit/probe behavior is claimed.
Local client mode/status parity passed. Record isolated read/write permissions,
option negotiation, retries, netascii/octet transfers and IPv4/IPv6 failures for
runtime/logging review. Server functional tests use the installed absolute path
and include root-required cases, so a host-loader/program fallback would not
qualify these candidates. Server/test-suite execution remains open.

## 2026-10-28 TFTP maintained test packaging

The existing C functional test and shell test now have native build/installation
targets. Timeout/exclusivity metadata and eleven test-package records match Make;
script and Kyua bytes match. Separate test archives preserve package ownership
of shared debug ancestors. No test source, daemon path or runtime assertions
were changed. This adds zero executed transfer cases; isolated installed daemon,
inetd, privilege and networking checks remain necessary.

## 2026-10-28 TFTP wrapper-disabled configuration

The existing configured graph now has independent Make evidence for disabled
TCP wrappers. The artifact removes libwrap and the three calls actually present
in the maintained LIBWRAP branch. No C source or logging/audit hooks changed.
No runtime authorization or transfer was exercised; disabled-wrapper operation
and access-control behavior still require isolated networking qualification.

## 2026-10-28 ntalkd

All six maintained source units, including shared ttymsg.c, compile unchanged
and match Make executable code/symbols. No DTrace or audit behavior is added by
this graph conversion. Invitation processing, terminal-write authorization,
delivery failures and logging remain isolated runtime review items. Build and
installation parity does not establish those behaviors; no daemon or terminal
announcement was executed on the host.

## 2026-10-28 mknetid

All three source units compile unchanged and match Make executable object code
and symbols. No direct SDT/DTrace, audit or syslog call was found in these
sources. This map-generation utility's error/output behavior and NIS default-
domain lookup remain runtime qualification items; no instrumentation was added.
The enabled native libc builds successfully, but its NIS behavior is not proved
by this component's build and installation comparison.

## 2026-10-28 mknetid diagnostics exercised

Explicit-file runtime qualification now checks duplicate warnings and their
quiet suppression, malformed passwd diagnostics, and required-file errors,
as well as supplementary groups and optional-file behavior. All six cases
match fixed expected results and Make under the same native loader/libraries.
No default-domain lookup, NIS service, live probes or audit stream is exercised.
These are external qualification checks; native Bazel test registration is
still outstanding.

## 2026-10-28 mknetid ATF registration catches harness failure

Registered six diagnostic/map cases in the maintained ATF suite. Both Bazel
runs abort in the dirname helper before any case body, at the capability-rights
validation assertion reached from stream-rights limiting. This is a real open
runtime compatibility gate; no instrumentation, capability check or assertion
was removed to obtain a pass. Exact rights/host compatibility diagnosis is
pending. Wrapper/Kyua build parity alone does not count as runtime coverage.

## 2026-10-28 Capsicum helper failure diagnosed

A descriptor-rights probe confirms that this running host returns the older
5BSD rights allocation: current libc rejects bits 0x6e000000 in word 1, while
host libc accepts the same returned rights. Some rights also changed meaning
at their old bit positions. Keep the assertion and the inherited-authority
intersection intact. Qualified execution requires a compatible kernel/runtime;
the mknetid ATF suite still has no passing runtime cases on this host.
The prior SDK/native harness split was removed because it did not solve this
ABI mismatch. See checkpoint and bazel-cap-rights-host-20261028 evidence.

## 2026-10-28 guest rights compatibility verified

The newer GENERIC kernel passes the static current-SDK descriptor-rights ATF
probe under the maintained networkless QEMU fixture runner. The returned mask
matches current CAP_ALL exactly and validates without suppressing assertions.
This contrasts with the older host's invalid mask and confirms the matching-
kernel route. No live DTrace/audit observation or mknetid ATF run is implied.
See bazel-rights-vm-20261028/run/result.json and serial.log.

## 2026-10-28 mknetid registered test bodies pass in QEMU

The six unchanged ATF shell bodies now pass with their Bazel runner/runfiles
replayed in a matching-kernel guest. This exercises duplicate/malformed/missing-
file diagnostics without disabling capability assertions or replacing helpers.
Evidence: bazel-rights-vm-20261028/mknetid-run-r3/serial.log and result.json.
The older-host failure remains reproducible; this is guest execution coverage,
not a passing host Bazel run or a live NIS service/DTrace/audit qualification.

## 2026-10-28 mknetid test archive

The unchanged six-case shell suite and Kyua index now have a standalone native
installation archive whose three metadata records and both payloads match Make.
This preserves diagnostic tests for installation; it adds no new runtime/probe
claims and does not establish complete-system test discovery.

## 2026-10-28 rpc.rwalld / rpc.rstatd / rpc.rusersd

Five C source units compile unchanged and match Make object code/symbols.
Existing syslog calls remain; no dedicated SDT/DTrace or audit call was found
in these sources. Remote wall executes the maintained wall command through
popen, so guest qualification must cover process invocation, terminal delivery
and authorization before runtime claims. rusers session disclosure and rstat
kernel/device statistics require actual RPC requests in isolation. Build and
installation parity does not establish those behaviors; no services started.

## 2026-10-28 pppoed

Native compilation preserves the maintained source and existing syslog/vsyslog
calls; its executable object matches Make. No dedicated DTrace/SDT or audit call
was found. Review guest coverage for module loading, netgraph node/hook creation,
discovery/session failures, fork/exec and configured command authorization.
No network or module-loading runtime was exercised in this build conversion.

## 2026-10-28 mail.local and smrsh

Both unchanged program objects match Make. Existing syslog diagnostics remain;
no dedicated audit/SDT/DTrace calls were found in their source files. Prioritize
isolated mailbox ownership/locking and delivery failure tests for mail.local,
and command allowlisting, path validation, metacharacter rejection and exec
failure tests for smrsh. No live mail, logging or authorization claim follows
from build/install parity. Custom SENDMAIL build flags remain unqualified.

## 2026-10-28 private libevent1

Eight maintained sources produce Make-identical ordinary/PIC executable code
and symbols. Build parity preserves existing logging and backend code but does
not establish event delivery, descriptor lifetime, timeout, signal, or teardown
behavior. Qualify kqueue/poll/select paths with consumers in a compatible guest;
no runtime or tracing coverage is claimed by this dependency conversion.

## 2026-10-28 tftp-proxy

Both native objects match Make executable code/symbols. Existing syslog and
PF error reporting remain unchanged; no dedicated audit/SDT/DTrace calls were
found in these two sources. Qualification still needs actual PF rule creation,
rollback/removal, malformed/failed transfer handling, privilege changes and
session cleanup under event-loop load in an isolated guest. No /dev/pf access
or network traffic was performed by this build/install comparison.

## 2026-10-28 private libevent1 installation

Private header, archive, DSO/link and debug packaging now match maintained
Make component metadata. Runtime source/logging behavior is unchanged. This
adds installation evidence only; readiness/timer/signal/backend and teardown
runtime qualification remains outstanding.

## 2026-10-28 ftp-proxy

Both compiled sources match Make executable code and symbols, preserving
existing syslog and privilege-drop code. No dedicated SDT/DTrace/audit calls
were found. Guest qualification must exercise FTP command/address handling,
PF rule creation/removal, dropped privileges, failures and concurrent sessions.
This conversion adds build/install evidence, not network or authorization proof.

## 2026-10-28 BOOTP subtree builds

Four programs compile unchanged with per-program defines preserved; 31 object
code/symbol comparisons match Make. Runtime review remains for configuration
parsing, address/interface lookup, gateway relay, vendor options, malformed
packets and service/client error reporting. No BOOTP traffic or live tracing
was exercised; installation and runtime qualification remain open.

## 2026-10-28 BOOTP installation

All four executable/debug payloads and five manual entries now have Make-parity
installation evidence, including the gateway manual hardlink. No runtime source
or logging was altered. BOOTP packet/configuration/relay/error behavior still
needs isolated execution; packaging checks do not supply that coverage.

## 2026-10-28 save-entropy and makewhatis.local

Exact maintained script bytes and manuals are preserved by native installation.
Existing entropy error logging remains unchanged. No script was executed;
qualify entropy-slot rotation/permissions/failure reporting and manual database
maintenance in isolated writable fixtures before runtime claims. Installation
parity does not establish random-device or maintenance behavior.

## 2026-10-28 blocklist helper scripts

Native archive payloads preserve both maintained scripts exactly, including
existing error messages and legacy-IPFW rejection. No firewall command was
executed. Runtime review remains for add/remove/flush, failed PF operations,
address/protocol parsing and legacy configuration errors in an isolated guest.
No security-policy correctness or live audit coverage is claimed by packaging.

## 2026-10-28 pkg-serve

The unchanged program object matches Make code/symbols. Preserve its existing
ATF file/mtime/malformed-request/traversal cases for native runtime integration.
Capability-mode containment and actual file service require execution on a
compatible kernel; build/install checks alone are insufficient. No repository
was served and no transport/authentication or policy correctness is claimed.

## 2026-10-28 pkg-serve ATF runtime coverage

All 14 maintained ATF assertions pass under captured Bazel runner/runfiles in
the matching-kernel guest, including malformed-request/error handling and the
existing traversal case. Shell assertions are unchanged; executable selection
is explicit through ATF configuration. This is bounded protocol coverage, not
an exhaustive confinement/authorization review or transport/signing proof.
The incompatible-host failures remain recorded. No host repository was served.

## 2026-10-28 pkg-serve test packaging verified

The maintained 14-case shell suite and Kyua index now match Make installation
bytes and metadata; tar ancestor directories are independently checked too.
This preserves the previously guest-exercised diagnostics/protocol assertions
for installation. No additional runtime, SSH, signing or audit claim is added.


### nuageinit installation (2026-10-28)

Native installation preserves the existing Lua program/module and manual bytes;
no source or observability behavior changed. Five Make metadata records and three
payloads match the qualified archive. Existing tests in libexec/nuageinit/tests
remain to be migrated and run in isolation; they exercise user creation, SSH
configuration and other system mutations. flua/module integration is pending.
No runtime, audit-event or DTrace coverage is claimed for this installation-only
change. Evidence: bazel-nuageinit-20261028-r2/qualification/installation-parity.json
under /usr/obj/usr/src.


### liblua native archives (2026-10-28)

All 32 sources are carried into ordinary/PIE native targets; 64 object text and
global-symbol comparisons pass against Make. Source scan found no DTRACE,
SDT_PROBE or audit() integration in the Lua C/header inputs. No probes were
removed or invented. Lua's language debug hooks are separate from OS audit and
DTrace coverage. Review audit needs at privileged flua/nuageinit operations when
those runtimes are qualified; this internal library build establishes no audit
or runtime behavior. Bootstrap and interpreter/module tests remain pending.
Evidence: /usr/obj/usr/src/bazel-lua-20261028-r2/qualification/parity.json.


### flua interpreter (2026-10-28)

The native target carries lua.c, linit_flua.c and modules/lposix.c unchanged,
including exported symbols needed by modules. All three object code/symbol
comparisons pass against Make. Five bounded runtime checks exercise language,
math, coroutines, built-in POSIX loading and error handling, not privileged
system mutations. Module-specific audit/security behavior, interactive readline
and bootstrap behavior remain open. Nuageinit runtime is not yet qualified.
Evidence: /usr/obj/usr/src/bazel-flua-20261028-r2/qualification/.


### flua lfs/fbsd modules (2026-10-28)

Original module sources are compiled unchanged; both PIC object code and symbols
match Make. Temporary filesystem operations, missing-path errors and fbsd API
argument rejection are checked with the exact built modules. This does not
establish process-spawn/pipe cleanup, privileged filesystem behavior, or audit
coverage of consumers. Keep those runtime/security checks open when qualifying
nuageinit and other privileged Lua users. Evidence:
/usr/obj/usr/src/bazel-flua-modules-20261028-r2/qualification/.


### flua hash module (2026-10-28)

Unchanged lhash.c is compiled against native libmd; object code and symbols match
Make. One-shot, incremental and binary output checks pass on four inputs for
native/Make modules. These checks do not establish context reuse after finalizing,
GC memory erasure, side-channel behavior or privileged consumer audit coverage.
The manual says uppercase hex while the existing implementation emits lowercase;
this pre-existing documentation discrepancy is recorded, not silently changed by
the build migration. Evidence: /usr/obj/usr/src/bazel-flua-hash-20261028-r2/
qualification/{parity.json,runtime/results.json}.


### flua jail module (2026-10-28)

Unchanged lua_jail.c is carried into native jail.so; object code and global
symbols match Make. Loading and seven invalid-type rejection checks pass,
without invoking jail operations. Kernel audit behavior for jail creation,
attachment, removal and parameter changes remains unverified and belongs in
isolated VM runtime qualification. No audit or privilege-enforcement completion
claim follows from these checks. Evidence:
/usr/obj/usr/src/bazel-flua-jail-20261028/qualification/.


### flua UCL module (2026-10-28)

Original lua_ucl.c is carried into native ucl.so with object code/symbol parity.
Typed in-memory configuration parsing, JSON roundtrip and malformed-input
rejection pass against the native libucl dependency. These checks do not qualify
file includes, schema validation, parser resource limits or privileged consumers'
audit behavior. Nuageinit integration remains open. Evidence:
/usr/obj/usr/src/bazel-flua-ucl-20261028/qualification/.


### private libyaml (2026-10-28)

All eight original C sources are declared in the native library target; ordinary
and PIC machine code/global symbols match Make. Build/install qualification does
not establish parser resource limits, malformed-input handling, emitter runtime
behavior or privileged consumers' audit integration. Runtime qualification will
continue through the flua YAML binding and its consumers. Evidence:
/usr/obj/usr/src/bazel-yaml-20261028/qualification/.


### flua YAML binding (2026-10-28)

Four original binding C files and four Lua files are carried forward. Object code
and Lua payload parity pass against Make. Mapping, serialization roundtrip, alias
and syntax-error checks pass using the archived Lua payload. These checks do not
establish hostile-input resource limits, exhaustive YAML semantics, or audit
coverage of privileged configuration consumers. Nuageinit integration remains
open. Evidence: /usr/obj/usr/src/bazel-flua-lyaml-20261028-r2/qualification/.


### flua FreeBSD kenv/linker modules (2026-10-28)

Original kenv.c and linker.c compile unchanged with object code/global-symbol
parity against Make. Manuals and nested installation paths are preserved. Runtime
kernel-environment and module load/unload behavior, privilege denial, cleanup and
kernel audit events remain unqualified; run those checks in an isolated VM.
No host kernel state was changed. Evidence:
/usr/obj/usr/src/bazel-flua-freebsd-20261028/qualification/parity.json.


### combined flua installation (2026-10-28)

All interpreter/module payloads match their qualified component archives. A
staged integration run imports all modules and exchanges YAML data through UCL.
No kernel environment, jail or module-loading operations are exercised; those
privileged behavior/audit gates remain open. This external run is not yet a
Bazel-owned test suite. Evidence:
/usr/obj/usr/src/bazel-flua-complete-20261028/qualification/.


### Bazel-owned flua runtime tests (2026-10-28)

Four maintained cc_test targets now execute the declared native interpreter,
loader, libraries, modules and Lua files. All pass: imports, hash known answer,
YAML/UCL interchange/error and temporary filesystem behavior. Sources/probes of
the interpreter/modules are unchanged. Privileged operation/audit checks remain
open; these tests import jail/kenv/linker without invoking their system mutations.
Evidence: /usr/obj/usr/src/bazel-flua-tests-20261028-r3/test-reports/.


### flua test-input invalidation (2026-10-28)

Added binary SHA-256 digest comparison to the Bazel-owned hash test. An unchanged
repeat used four cached results; this Lua file change reran all four shared-script
tests without compile/link work. Production artifacts stayed byte-identical.
This verifies execution of the updated assertions, not privileged runtime/audit
coverage. Evidence: /usr/obj/usr/src/bazel-flua-cache-qualification-20261028/.


### nuageinit test payload migration (2026-10-28)

Three ATF scripts and fourteen Lua fixtures install byte-identically to Make;
crypt helper code/global symbols match. Existing assertions, including user,
SSH, hostname, timezone and authorization configuration scenarios, are preserved.
These cases have not executed under the new native test path and their audit or
privilege behavior is not qualified. Root-only cases require isolated VM coverage.
Evidence: /usr/obj/usr/src/bazel-nuageinit-tests-20261028-r3/qualification/.


### nuageinit native Lua fixtures (2026-10-28)

Five unchanged fixtures now execute under Bazel with native flua and declared
nuage/lfs inputs. Pathname, file overwrite/append, base64, hostname validation/file
generation and SSH configuration rewriting checks pass under NUAGE_FAKE_ROOTDIR.
No host configuration or users changed. ATF shell-level expectations, live service
behavior and user-management/audit operations remain unqualified. All four flua
regression tests also reran successfully with the extended test launcher.
Evidence: /usr/obj/usr/src/bazel-nuageinit-runtime-20261028/test-reports/.


### pw native build (2026-10-28)

All fifteen original C files are carried forward, including pw_log.c; object code
and symbols match Make. Source scan found no direct audit(), DTRACE, SDT_PROBE
or syslog references in these C files. That does not establish absent kernel
syscall auditing or adequate account-management audit coverage. Review configured
pw logging, failed mutations and kernel audit behavior during isolated runtime
qualification. No user/group operations executed on the host. Evidence:
/usr/obj/usr/src/bazel-pw-20261028/qualification/.


### pw ATF unit execution (2026-10-28)

Seven existing descriptor parsing cases pass with native program/runtime inputs,
including forked invalid/negative/overflow diagnostics and EX_USAGE checks.
Existing unit assertions/stub remain unchanged. This does not qualify user/group
mutation logging, syscall audit, password database locking or privilege handling.
Evidence: /usr/obj/usr/src/bazel-pw-unit-20261028/test-reports/.


### pwd_mkdb native subprocess tests (2026-10-28)

Six existing ATF scenarios pass using native libc/libsys and explicit native rtld
for both harness and generator subprocesses. Real database records and metadata
are checked. Host account databases remain unchanged. Failure preservation and
shell-policy checks here do not establish kernel audit event coverage, concurrent
locking or root-only user-management flows. Evidence:
/usr/obj/usr/src/bazel-pwd-mkdb-native-20261028/test-reports/.


### pwd_mkdb installed ATF artifacts (2026-10-28)

ATF binary/Kyua/debug installation now matches runtime-tests metadata from Make.
Make caught const-dropping casts in the new optional-loader helper; replaced with
checked string copies and reran all six database cases successfully. No assertion
or expected diagnostic was weakened. Broader privilege/audit coverage remains
open. Evidence: /usr/obj/usr/src/bazel-pwd-mkdb-test-install-20261028-r2/.


### DMA mailbox helper (2026-10-28)

Unchanged dma-mbox-create.c carries its existing Capsicum and syslog integration
into the native target; machine code/global symbols match Make. Root:mail and
04554 metadata are preserved. No privilege transition, mailbox write or syslog
runtime event is claimed: qualify success/failure paths and audit behavior in an
isolated VM. Evidence: /usr/obj/usr/src/bazel-dma-mbox-20261028/qualification/.

### 2026-10-28 DMA aliases generators

Native yacc/lex rules now generate the unchanged DMA alias grammar and scanner,
including the explicitly declared yacc interface file. Four generated artifacts
match Make except exact preprocessor path spelling (evidence:
/usr/obj/usr/src/bazel-dma-generators-20261028/generator-parity.json).
No application observability behavior changed. Agent compile/runtime, malformed
aliases, delivery failure logging and privilege behavior remain unqualified.

### 2026-10-28 DMA agent compilation

All twelve agent objects now match Make .text and global/undefined symbols.
Existing delivery, queue ownership and failure syslog calls are carried forward
unchanged. This is build evidence, not verification that logs reach a running
logger. Mail submission, TLS, queue retries, privilege transitions and audit
coverage still need isolated runtime qualification. No probes or audit hooks
were added during this conversion.

### 2026-10-28 DMA agent installation

Installation parity now covers mail-group executable/debug ownership, setgid
mode, restrictive configuration modes, config package tags and manual hardlink.
This does not demonstrate mail delivery or logging at runtime. Queue retries,
SMTP/TLS failure reporting and privileged mailbox behavior remain on the runtime
qualification list. Evidence: bazel-dma-agent-install-20261028/qualification/dma/parity.json.

### 2026-10-28 ypxfr and native RPC libc dependency

Nine ypxfr object bodies and symbols match Make. Existing yp_error/vsyslog
reporting is preserved; no new DTrace or audit instrumentation was added.
Install/debug metadata and executable dependencies now match Make. Five RPC
consumers retain matching symbols/dependencies, and rpcsvc static archives are
byte-identical after the dependency change. Live map transfer, peer validation,
partial-write cleanup, syslog delivery and audit coverage remain unqualified.
Evidence: bazel-ypxfr-install-20261028/qualification/ypxfr/parity.json and
bazel-rpcsvc-native-libc-regression-20261028-r2/regression-parity.json.

### 2026-10-28 Hyper-V helper scripts

All five script payloads are unchanged and installation metadata matches Make.
The scripts consume /etc/rc.subr and network configuration; hv_set_ifconfig also
edits /etc/rc.conf. Interface reconfiguration, virtual-function failover,
command failures and reporting still require isolated Hyper-V runtime testing.
No host networking was changed. No probes/logging hooks were added during this
packaging conversion. Evidence: bazel-hyperv-scripts-20261028/qualification/hyperv/parity.json.

### 2026-10-28 main rc files

Fourteen rc/default/helper payloads and their installation metadata match Make.
No shell source or logging behavior changed. Startup, shutdown, diskless setup,
suspend/resume and network transitions remain runtime qualification requirements.
Existing rc tests and the full rc.d service collection are not covered by this
nonrecursive installation comparison. Evidence: bazel-rc-core-20261028-r2/qualification/rc/parity.json.

### 2026-10-28 always-installed rc.d service groups

Ninety unchanged scripts across fifteen groups now have native installation
metadata matching Make. This carries forward existing service startup/logging
commands, including mac_abacd, syslogd and NFS services, without executing them.
Start/stop/restart behavior, error reporting, rc ordering and service dependencies
remain runtime test requirements; no daemon functionality is established by
script packaging parity. Conditional groups are not covered by this result.
Evidence: bazel-rc-services-20261028/qualification/rc/parity.json.

### 2026-10-28 conditional rc groups using shared settings

Eighteen additional unchanged scripts (audit, jail, PF, NIS, nscd and gssd) now
follow native configuration selection. Enabled and disabled installation payloads
match Make. This establishes selection and metadata parity, not daemon startup,
audit delivery, firewall behavior, jail creation or NIS communication. No service
was started on the host. Other optional rc groups and runtime tests remain open.

### 2026-10-28 all single-option rc service groups

The selected-service table now covers 31 single-option groups, with 158 scripts
including unconditional services when enabled. All-on/all-off payload and
metadata parity pass against Make. No script source changed. This includes SSH,
NTP, sound, wireless and ZFS service scripts but does not prove those services
start, authenticate, log correctly or communicate with hardware. ACPI, Kerberos
alternatives and KTLS conjunction remain separate pending work.

### 2026-10-28 compound rc service selection

ACPI architecture selection, MIT/Heimdal alternatives and KTLS prerequisites now
have native installation expressions. Enabled variants and disabled prerequisites
match Make metadata/payloads. Architecture checks inspect configured dependencies
only. The scripts remain unchanged; power management, Kerberos authentication,
TLS offload, error reporting and boot ordering still need runtime qualification.
No service was started or host configuration changed.

### 2026-10-28 rc ATF installation

All eleven maintained rc shell-test wrappers and Kyua metadata match Make.
No test assertions changed and no cases executed. Installed-system/root cases
need isolation; existing integrity-related cases require applicability review
without reintroducing out-of-scope BIP. Source-fixture tests should use declared
native inputs. Packaging these tests does not prove startup or logging behavior.

### 2026-10-28 safe_eval execution

Both maintained safe_set assertions pass with native Bazel tools in a matching-
kernel QEMU replay. Host execution aborts before assertions due to Capsicum ABI
mismatch. This verifies two shell-input filtering cases only, not general rc
startup or privileged service behavior. Source-path selection uses standard ATF
configuration; assertions and safe_eval implementation are unchanged.

### 2026-10-28 os-release startup fixture cases

Three existing cases pass using native Bazel payloads in matching-kernel replay:
metadata creation, denied install preservation, and input/temporary-file failures.
Their existing fixtures replace external operations with temporary-file seams;
this is not an actual system startup. Missing native env/libutil runtime was
caught and fixed. All rc test installation payloads still match Make. No host
os-release file or installed configuration changed.

### 2026-10-28 SSH/syslog startup fixture tests

Seven existing fixture cases pass with native Bazel payloads in QEMU replay:
key-generation failure handling, disabled/existing key logic, prechecks, socket
preparation/read failures, chroot lists and explicit quoted paths. Existing stubs
and temporary fixtures are preserved. This does not demonstrate live SSH login,
real key generation, syslog delivery or boot ordering. Native /bin/sh is staged
for existing shebangs in the private VM; host state is untouched.

### 2026-10-28 ATF pytest wrapper

Native target preserves the existing source's stderr diagnostics, debug argument
printing and execvp failure reports. The source contains no DTrace probes or
audit calls. This unprivileged test-launch adapter does not introduce a new
privileged policy operation; no new audit instrumentation added. Build and
installation parity pass; actual pytest dispatch/runtime remains unqualified.

### 2026-10-29 ATF shell test installation

All existing shell-test bodies and diagnostics are preserved. Generated wrapper
bytes and the integration interpreter substitution match Make; hierarchy
discovery uses the existing Kyuafile. No new DTrace or audit instrumentation
was needed for this installation-only change. Kernel-module-related and other
ATF test behavior has not been executed or qualified by these archive checks.

### 2026-10-29 runtime-linker test source closure

Restored common.c/common.h to native set_var_test, matching Make's source list.
Its helper functions and ATF failure reporting are now present in the installed
ELF as well as the other fd-loading tests. The broader recursive symbol check
caught the omission. Test source/assertions are unchanged; no new runtime result
or DTrace/audit instrumentation is claimed.

### 2026-10-29 twelve /bin shell suites

Preserved all existing test bodies and diagnostics for chmod, cp, date, hostname,
ln, ls, mkdir, mv, pwd, rm, rmdir and test. No DTrace/audit calls were found in
these shell test bodies; no instrumentation added for installation-only work.
Kyua unprivileged-user and required-file constraints are retained. Runtime and
privileged filesystem behavior are not qualified by these payload comparisons.

### 2026-10-29 imported dd/expr/sleep suites

Existing test assertions and diagnostics are preserved. expr applies exactly
Make's command/diagnostic substitutions; sleep's missing Make registration is
restored. This change concerns test installation, not production dd/sleep probes
or runtime audit coverage. No new instrumentation or runtime success claimed.

### 2026-10-29 /bin aggregation

No production sources or probe declarations changed. Chflags test installation
preserves its existing assertions/diagnostics. Pkill's redundant direct libelf
link was removed while retaining libkvm's declared dependency. Aggregate build
and ELF interface checks do not establish live tracing, audit or process-control
runtime behavior; those gates remain separate.

### 2026-10-29 /sbin shell suite installation

Existing test bodies and diagnostics preserved for md5, mdconfig, nvmecontrol,
route, bectl and growfs. No production source or DTrace/audit declaration was
changed. A source scan found no explicit SDT/DTRACE/audit references in their
C/header files; this is an instrumentation review candidate, not evidence that
kernel-level syscall audit/tracing is absent. Installation parity does not prove
runtime tracing, audit, ZFS, device or network behavior.

### 2026-10-29 devd client test

Preserved both stream and seqpacket test bodies and diagnostics. No runtime
probe/audit qualification performed. Production devd migration is still pending;
Make conditionally compiles devd_provider.d with WITH_DTRACE, which must be
carried into its native graph. The current devd BUILD file only installs nvmf.conf.

### 2026-10-29 devd provider migration

Native devd now carries devd_provider.d through header generation, compiled-object
probe rewriting and provider linkage. Provider attributes, argument mappings,
function/probe schemas and site counts match fresh Make output: nine ordinary
and twelve enabled sites validated against function bounds and instruction bytes.
DTrace-disabled output has no DOF. No live probe firing or audit runtime claim.

### 2026-10-29 md5 archive/Casper selection

No production source or probe/audit declaration changed. Casper selection now
matches Make's optional capability-service integration. ELF parity verifies the
selected dependency interface, not live capability-service or audit behavior.

### 2026-10-29 recursive /sbin parity fixes

No production sources or probe definitions changed. mdconfig drops redundant
direct libbsdxml/libsbuf linkage while preserving libgeom's own dependency graph.
Installation and ELF interface checks do not establish live tracing, audit,
device-management, network or ZFS behavior. Those runtime gates remain open.

### 2026-10-29 resizewin, runat, mdo, pom and mididump

No explicit SDT/DTRACE/audit references found in these five utility C/header
sources. Source scan is not evidence of absent kernel syscall tracing or audit.
No sources modified. mdo's credential/authorization behavior warrants a dedicated
runtime audit review; resizewin terminal and mididump device behavior also remain
unqualified. Current evidence covers installation and ELF interfaces only.

### 2026-10-29 command, lorder and ssh-copy-id

Script bodies and lorder test assertions are installed unchanged. No probes or
audit hooks added or removed. ssh-copy-id's remote authentication/key-installation
behavior was not exercised; installed byte equality is not runtime qualification.

### 2026-10-29 newgrp/passwd

No explicit SDT/DTRACE/audit references found in these command sources; passwd
includes syslog.h and delegates authentication/password changes through PAM.
That scan does not determine kernel or PAM audit coverage. Preserve sources and
review authentication success/failure audit behavior during VM qualification.
No runtime authentication or credential operation was performed in this batch.

### 2026-10-29 su audit and provider migration

Preserved existing audit_submit call sites for authentication/account/session
outcomes and the su provider. Enabled binary matches Make's probe schemas and
two patched ordinary sites, with libbsm declared; disabled configuration removes
the audit dependency and DOF. Sources unchanged. Live audit success/failure
records, probe firing and PAM/credential semantics require VM qualification.

### 2026-10-29 rctl, who and gcore

No explicit SDT/DTRACE/audit references found in these command C/header sources.
This does not establish absence of kernel tracing/audit. No source modifications.
Review resource-control updates and process-attachment/core-dump auditing during
VM runtime qualification; current evidence covers installation and ELF interfaces.

### 2026-10-29 w/uptime

No explicit SDT/DTRACE/audit references found in local w C/header sources.
Production sources and shared ps formatter unchanged. Kernel/libkvm process-query
and login-session behavior remain runtime qualification items; source scanning
and ELF parity do not establish live tracing/audit coverage.

### 2026-10-29 sockstat

Preserved socketsnapshot provider and tracing wrapper. Native/Make schemas and
two ordinary/two enabled patched sites match; disabled variant omits DOF. No
explicit audit references found in command C/header sources; kernel auditing may
still apply. Live snapshot tracing, Casper IPC and output tests remain pending.

### 2026-10-29 sockstat parsing tests

Eleven maintained parsing cases executed successfully through native Bazel ATF
runners; assertions and source preserved. These cases test port selection parsing,
not live socket snapshot probes, Casper IPC, kernel auditing or service behavior.

### 2026-10-29 netstat

No explicit DTRACE/SDT/audit references found in command C/header sources and no
provider in its maintained Makefile. No instrumentation added or removed. Source
scan does not establish kernel tracing/audit coverage; live statistics and route
query behavior remain runtime qualification items.

### 2026-10-29 mkuzip

No explicit DTRACE/SDT/audit references found in local mkuzip C/header sources.
No instrumentation or production sources changed. Compression/thread scheduling,
image mounting, kernel tracing and audit behavior remain runtime qualification
items; installation/ELF parity alone does not establish them.

### 2026-10-29 etdump

No explicit DTRACE/SDT/audit references found in local etdump C/header sources.
No instrumentation/source modifications. Parsing real and malformed boot images,
including shared conversion routines, remains a runtime qualification item.

### 2026-10-29 mkimg

No explicit DTRACE/SDT/audit references found in local mkimg C/header sources.
No sources/instrumentation changed. Installation and ELF parity do not qualify
image layout, sparse I/O, format compatibility, or kernel/device audit behavior.
Existing image/offset tests remain to be migrated and executed.

### 2026-10-29 mkimg test declarations (not runtime-qualified)

The 160 image-format/scheme/geometry/sector cases and 10 partition-offset
regressions are declared with original shell bodies and expected fixtures.
Execution is blocked at source-built jot fixture generation by the already
recorded host/source Capsicum rights ABI mismatch. No DTrace probes or audit
hooks were introduced or removed. No runtime, image bootability, disk I/O,
memory, or performance claim follows from this batch. See checkpoint evidence.

Mkimg follow-up: declared bootstrap jot resolves fixture generation; exact
installation parity passes in bazel-mkimg-tests-20261029-r4. Native ATF startup
still hits the documented host Capsicum ABI failure; no image/runtime or
performance qualification is claimed. Original probes/audit behavior is unchanged.

### 2026-10-29 morse, random and vtfontcvt

Native migration preserves the maintained production sources. Focused source
inspection found no direct DTrace/SDT or audit submission calls. Morse retains
its optional speaker/TTY access and ioctls; those device paths require separate
runtime qualification. Random retains its normal entropy/file paths, and
vtfontcvt its output file/font compression behavior. No new privileged boundary
or observability mechanism was introduced; syscall audit coverage is not
established by build/metadata parity. Device and file-format runtime coverage
remains open rather than adding migration-only probes.

### 2026-10-29 wg

Native migration retains all subcommands and the FreeBSD interface-control and
userspace IPC sources. Focused inspection found no direct DTrace/SDT or audit
submission hooks. Interface/key configuration is security-sensitive: system
qualification should check authorization and syscall audit behavior without
logging private keys. No migration-only instrumentation was added. Build and
installation parity do not qualify live interface changes, peer handshakes,
cryptographic vectors, credential boundaries or observability of updates.

### 2026-10-29 iscsictl / libiscsiutil

Migration retains libiscsiutil syslog handling, CHAP processing and iscsictl's
CAM/iSCSI ioctls. Focused inspection found no direct DTrace/SDT or audit submission
hooks. Session creation/modification/removal, credential handling and module/device
access need VM qualification and audit review. Existing logging is not proof of
security audit coverage; secrets must not be added to instrumentation. No live
sessions, device operations or source instrumentation changes occurred here.

### 2026-10-29 genl and quota

Native migration preserves existing sources and quota's setuid installation
metadata. Focused inspection found no direct DTrace/SDT or audit submission
hooks. Installed credential behavior, quota authorization, remote RPC and
netlink interaction require separate runtime qualification; metadata parity
alone proves none of these. No migration-only instrumentation was introduced.

### 2026-10-29 xo CLI

Native migration preserves the formatting CLI and library calls. Focused CLI
source inspection found no direct DTrace/SDT or audit submission hooks. No new
privileged boundary or instrumentation is introduced. Format/error/locale tests
remain pending; successful linking to libxo is not functional output proof.

Xo test follow-up (2026-10-29): all eight maintained format cases are declared
with unchanged assertions and fixtures. Recursive installation parity passes;
the attempted text case fails in ATF startup on the incompatible host Capsicum
ABI. Formatting/runtime behavior and observability remain unqualified by this
attempt. No production instrumentation or authority behavior changed.

### 2026-10-29 pkgconf / libpkgconf

Maintained package audit-log handling in libpkgconf/audit.c is retained. This
logs package-resolution activity; it is not evidence of OS security-audit
integration. No production instrumentation or privilege boundary was changed.
Environment-controlled paths, sysroot handling and downstream build behavior
remain runtime qualification items. CLI install parity does not establish them.

### 2026-10-29 bomtool and spdxtool

Native migration retains package metadata, licensing and serialization sources.
Focused inspection found no direct DTrace/SDT or OS audit submission hooks.
Build/install parity does not validate generated inventory correctness or license
interpretation. Functional document and input-error coverage remains open; no
new privileged boundary or migration-only instrumentation was introduced.

### 2026-10-29 mail

Native rules retain all 23 maintained C sources and five local headers.
Focused C/header scan found no explicit DTrace/SDT, audit_submit/auditon or
setuid/setgid call sites. No probes or audit calls were removed or invented.
Four maintained signal/dead.letter tests pass with the native mailx executable;
mail delivery, mailbox permissions and editor/shell invocation remain runtime
coverage gaps. Consider mail submission/error observability in a separate
behavioral review; this build migration introduces no production policy changes.

### 2026-10-29 whois and FTP client

Focused WHOIS/tnftp source/header scan found no explicit DTrace/SDT,
audit_submit/auditon or setuid/setgid call sites. Native rules retain all
maintained sources and FTP IPv6 configuration without adding/removing probes.
Network transactions, credentials, transfers, proxy/active/passive paths and
WHOIS referrals remain runtime coverage gaps. Any new audit policy needs a
separate behavioral/security review, not inferred from build/install parity.

### 2026-10-29 fortune group

Fortune, strfile and unstr retain their maintained source and shared format
header. Focused source inspection found no explicit DTrace/SDT/audit-submit
integration to carry forward. Exact installed tip/index bytes and three ELF
pairs are compared; random choice, regex/locale behavior and malformed database
handling remain runtime coverage gaps. Index generation executes the declared
native strfile; it does not substitute a synthetic database or host PATH tool.

### 2026-10-29 locate group

Native rules preserve locate.bigram's Capsicum helper calls and all source/header
inputs; no explicit DTrace/SDT/audit_submit/auditon sites were found in focused
C/header scanning. Fifteen host runtime encoding/query comparisons succeeded;
both Make/native bigram binaries fail host loading for missing
cap_rights_intersect@FBSD_1.9 and remain unqualified. Maintenance scripts and
filesystem visibility/privacy behavior require separate runtime qualification.
No source checks or capability calls were removed to bypass host limitations.

### 2026-10-29 tip/cu

Native rules preserve ACULOG and PRISTINE, loginit/logent and the maintained
seteuid/setegid transitions. Source scan found no explicit DTrace/SDT or
OS audit_submit/auditon calls. ACU accounting is not OS audit integration.
Keep serial sessions, lock ownership, privilege transitions, shell escapes,
transfers and logging/privacy behavior on the runtime review list. No source
behavior or privilege checks were modified to achieve build parity.

### 2026-10-29 man/mandoc

Native rules preserve the man shell frontend and all 61 formatter/database C
sources. Focused mandoc C/header scan found no explicit DTrace/SDT or
OS audit_submit/auditon integration. Rendering evidence covers three pages and
five formats with explicit SDK libraries; host libc failure remains recorded.
Manual-database writes, package-trigger execution and man pager/shell lookup
remain runtime review items. Package trigger contents and application source
policy were not modified as part of the migration.

### 2026-10-29 host/drill

Native targets retain all maintained DNS-client sources, resolver/crypto
library dependencies and drill's trust-anchor default. Focused client C/header
scan found no explicit DTrace/SDT or OS audit_submit/auditon integration.
DNSSEC validation failures, resolver transport/timeouts and trust-anchor
loading remain runtime/observability review items. No audit/probe hooks or
security decisions were changed to obtain build parity.

### 2026-10-29 gprof

Native rules retain all maintained profiling-analysis sources and explanatory
data. Focused C/header scan found no explicit DTrace/SDT or audit_submit/auditon
sites. gprof profile analysis is distinct from DTrace probe integration; this
build check does not establish producer instrumentation or profiling accuracy.
Profile generation, kernel inputs and call-graph/output checks remain open.

### 2026-10-29 truss

Native build retains ptrace/process-descriptor handling, Capsicum helpers,
syscall filters and libsysdecode. No explicit DTrace/SDT or audit_submit/auditon
sites were found in focused local C/header scanning; syscall observation through
ptrace is distinct from adding DTrace/audit integration. All 17 maintained ATF
cases are declared but fail before their bodies at the documented host Capsicum
ABI mismatch. None is runtime-qualified. Preserve process lifecycle, ABI
translation, syscall filtering and privilege/capability checks for matching-kernel
qualification; no source checks were weakened to bypass this host limitation.

### 2026-10-29 bmake

Native rules retain meta/trace and filemon support, including declared kernel
filemon ioctl headers. No explicit DTrace/SDT or audit_submit/auditon sites were
found in focused source scanning. Filemon records are distinct from DTrace/OS
audit integration. 398 selected maintained unit-output comparisons and Lua
expectation check pass; /dev/filemon-dependent cases are excluded by the suite
and remain open, along with real ports/meta-mode dependency monitoring.

### 2026-10-29 bc/dc

Native targets preserve arithmetic/runtime sources, generated libraries/help,
error handling, NLS catalogs and libedit. Focused C/header scanning found no
explicit DTrace/SDT or audit_submit/auditon sites. Maintained selected bc/dc
suites pass with saved native binaries; generated/problematic cases, interactive
history/terminal and locale coverage remain open. No runtime/security logic or
expected test outputs changed to obtain build or suite parity.

### 2026-10-29 bc/dc fixture installation follow-up

Native tests-enabled installation now includes the complete maintained fixture
patterns and both plain test wrappers, verified against Make. No production
source, expectations, probes or audit behavior changed. Earlier host suite
passes remain separate from native Bazel test registration and installed-image
runtime qualification, which are still outstanding.

### 2026-10-29 Bluetooth user libraries and clients

Reviewed lib/libbluetooth, lib/libsdp and usr.bin/bluetooth source/build files.
No explicit DTrace provider/SDT probes or direct audit calls were found in these
components. Native declarations preserve their maintained source inventory;
no instrumentation was removed. Review candidates include rfcomm_sppd session
establishment/failure and service registration through libsdp. This is an
observability follow-up, not a claim that kernel socket auditing is absent.
Kernel Bluetooth modules and operational auditing were not qualified here.

### 2026-10-29 lutok

No explicit DTrace/SDT or direct audit calls found in contrib/lutok or
lib/liblutok. The native ordinary/PIE libraries preserve all maintained sources.
Lua exception translation and stack cleanup need consumer runtime coverage;
archive parity alone does not qualify those behaviors.

### 2026-10-29 SQLite

No explicit DTrace/SDT or direct audit calls found in the maintained sqlite3.c
amalgamation or lib/libsqlite3 build files. Native build preserves that source
and uses native libthr, whose separate instrumentation is retained. SQLite
transaction/locking/recovery behavior needs runtime tests through consumers;
binary/installation comparisons do not qualify it.

### 2026-10-29 Kyua

No explicit SDT/DTrace or direct audit calls found in reviewed Kyua C++ sources.
Native source inventory preserves logging, results and jail implementation.
Jail/module preparation remains an audit-review candidate; no privileged
operation was exercised. Plain-test reporting passed with host runtime libraries.

### 2026-10-29 mlx4 user provider

No explicit SDT/DTrace or direct audit calls found in libmlx4 sources/build files.
Native target retains all seven maintained source files. RDMA resource lifecycle,
error paths and kernel/provider observability require hardware/runtime review;
archive/ELF parity does not qualify them. No kernel driver conversion is claimed.
