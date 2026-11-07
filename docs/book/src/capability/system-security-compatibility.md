# Hardened-system compatibility qualification matrix

## Acceptance contract

This is an **all-base plus 100 third-party candidates test backlog**, not a
compatibility certification. C01–C30 are initial base scenarios; the exhaustive
package-object inventory, expanded base families and capability-provider matrix
below define the remaining base scope. C31–C130 are third-party candidates.
Selection is based on practical coverage, not a measured popularity ranking.
All rows start NOT RUN for this matrix's integrated acceptance contract; earlier
component evidence is supplementary and must be linked explicitly when reused.

Use the same selected third-party package payload hashes on conventional and
hardened 5BSD. No BIP-specific source patches, privileged wrappers, mandatory
capability conversion, or disabled enforcement may be hidden behind a pass.
Normal ports patches and explicit install/configuration paths are allowed and
must be identical or have their differences recorded. Ordinary software installs
outside the immutable base and keeps normal UNIX authorization. Protected base
modification and protected-service admission have separate negative tests.

## Execution and evidence

- Run one qualification VM at a time. Never install these packages or change
  authentication, networking or services on the host.
- Build/package with the maintained workflow and `/usr/obj` publication paths;
  use `/usr/obj/5BSD-ports` through `PORTSDIR`. Do not create a second home repo.
- Pin package versions, origins/flavors/options, source revisions, dependency
  closure, payload hashes and fixture inputs before each run. Origins below are
  candidates, not a requirement to freeze those versions indefinitely.
- Each applicable package must install, execute real work, restart, retain its
  persistent state across clean reboot, upgrade, and uninstall safely. Test
  executable rollback only against a compatible retained data format. Never
  automatically roll back shared database/user data with the OS or application.
- Record kernel/generation hashes, BIP state, package inventory, configuration,
  commands, exits, expected and actual outputs, serial logs and clean shutdown.
  A version string, running PID, skipped test or missing error is not a pass.
- Status vocabulary: NOT RUN, PASS, FAIL, BLOCKED, UNSUPPORTED. Record baseline
  failure separately from hardened-only failure; unsupported is not passing.
- Network tests use isolated fixture peers with pinned inputs; real peer traffic
  is required. Keep one QEMU VM, using isolated jail/VNET peers where suitable;
  if a test needs another VM, record that prerequisite rather than exceeding
  the current single-VM limit. No public mail, DHCP, DNS or NFS service exposure.
- Browser tests require a working display stack and real multi-process behavior.
  Headless-only evidence cannot qualify GUI, GPU, audio or physical devices.
- Ordinary unsigned applications must be covered where owner policy allows them;
  package/application signatures must not confer base-release authority.

## Initial execution slice

Start with C01, C02, C03, C04, C05, C07, C08, C10, C11, C12, C13, C24, C28,
C31, C41, C44, C51, C67, C69 and C72 (20 items). This covers boot, authentication,
SSH, logs, scheduling, storage/package lifecycle, Python, PostgreSQL, SQLite,
nginx, sudo, rsync and Git. Expand to the remaining rows after this foundation
works; the remaining rows stay required backlog, not implicitly accepted.

## Availability review

All 100 third-party origins had a Makefile in the selected custom ports checkout
at review time. This is recipe presence only: it proves neither build success,
package availability, ABI compatibility nor runtime support. Resolve flavors,
IGNORE/BROKEN/architecture constraints, dependencies and optional features through
the maintained ports/package workflow. Preserve failure reasons.

Reviewed ports HEAD: `3fd982c4de5ab72d93eddb7a2414bcc81b20bace` (working-tree recipe hashes are in the review record).

## Base system

| ID | Component | Candidate origin | Required exercise | Status |
| --- | --- | --- | --- | --- |
| C01 | Boot and shutdown | Selected base packages | Normal packaged rc startup; clean shutdown; second boot with retained state | NOT RUN |
| C02 | Console login | Selected base packages | Correct and incorrect password; non-root session; logout and login records | NOT RUN |
| C03 | PAM stacks | Selected base packages | Authentication, account expiry, password change and session hooks; deny cases | NOT RUN |
| C04 | su | Selected base packages | Root to user and password-authenticated user to root; wheel rejection and environment | NOT RUN |
| C05 | passwd | Selected base packages | Change own password; old password rejected; database persistence after reboot | NOT RUN |
| C06 | pw account administration | Selected base packages | Create, modify and remove disposable users/groups; ownership and supplementary groups | NOT RUN |
| C07 | NSS/account lookup | Selected base packages | Local and configured directory users/groups; unavailable backend; ordinary daemon startup | NOT RUN |
| C08 | OpenSSH server | Selected base packages | Normal rc-started sshd; external public-key and PAM login; denied credentials; restart | NOT RUN |
| C09 | OpenSSH client and agent | Selected base packages | Host-key verification; ssh-agent keys; forwarding under explicit policy | NOT RUN |
| C10 | SFTP and SCP | Selected base packages | External upload/download; ownership, permissions, rename and checksum checks | NOT RUN |
| C11 | syslogd and logger | Selected base packages | Send unique messages through normal sockets; verify configured files and restart | NOT RUN |
| C12 | newsyslog | Selected base packages | Force selected fixture-log rotation; signal daemon; verify new and rotated contents | NOT RUN |
| C13 | cron | Selected base packages | User and system jobs create timestamped output; crontab permissions and reboot persistence | NOT RUN |
| C14 | at and batch | Selected base packages | Submit, execute and remove disposable jobs; queue permissions and spool writes | NOT RUN |
| C15 | ntpd | Selected base packages | Configured local test peer; startup and drift-state writes; clock tests only in disposable guest | NOT RUN |
| C16 | DHCP client | Selected base packages | Lease acquisition, renewal and persisted lease data on isolated virtual network | NOT RUN |
| C17 | DNS resolver | Selected base packages | Local test DNS with positive, negative and timeout responses; resolver configuration | NOT RUN |
| C18 | IPv4/IPv6 networking | Selected base packages | Addresses, routes, TCP/UDP and loopback; network restart without losing state | NOT RUN |
| C19 | PF firewall | Selected base packages | Load explicit test rules; allowed and blocked traffic; counters and reload | NOT RUN |
| C20 | NFS client | Selected base packages | Mount isolated export; file create/read/rename; permissions and reconnect | NOT RUN |
| C21 | NFS server | Selected base packages | Export ordinary dataset; client operations and UID mapping; protected-base export rejection | NOT RUN |
| C22 | NFS locking/RPC | Selected base packages | Concurrent advisory locks with a peer; conflict, release and reconnect | NOT RUN |
| C23 | UNIX filesystem semantics | Selected base packages | Modes, ACLs, extended attributes, hardlinks, symlinks, atomic rename and mmap | NOT RUN |
| C24 | ZFS ordinary datasets | Selected base packages | Create allowed data files; snapshots, restore and persistence; protected-boundary denial | NOT RUN |
| C25 | Jails | Selected base packages | Start ordinary writable jail; package install, service operation and clean removal | NOT RUN |
| C26 | VNET jails | Selected base packages | Network-isolated jail; addresses, DNS and connections; shared-network alternative | NOT RUN |
| C27 | Device services | Selected base packages | Normal devd startup; terminal and device permissions; virtual hotplug; physical devices separate | NOT RUN |
| C28 | pkg lifecycle | Selected base packages | Install, upgrade and remove a third-party package; dependencies, scripts and configuration retention | NOT RUN |
| C29 | Base build/package tools | Selected base packages | Compile small native program then qualify maintained world/kernel/packages build workflow | NOT RUN |
| C30 | Boot-environment lifecycle | Selected base packages | Create new base generation, select, confirm, rollback and retire; retain shared data | NOT RUN |

## Runtimes

| ID | Component | Candidate origin | Required exercise | Status |
| --- | --- | --- | --- | --- |
| C31 | Python | `lang/python313` | venv, pip from pinned offline inputs, native extension import, multiprocessing, SSL and bytecode cache | NOT RUN |
| C32 | Node.js | `www/node22` | npm offline install, native addon, HTTP service, worker threads and child process | NOT RUN |
| C33 | Ruby | `lang/ruby34` | Bundler/gem install from pinned inputs, native extension and persistent service | NOT RUN |
| C34 | Perl | `lang/perl5.40` | Local module install, XS extension, subprocess and network I/O | NOT RUN |
| C35 | PHP | `lang/php84` | PHP-FPM request, extension loading, sessions, sockets and logs | NOT RUN |
| C36 | Lua | `lang/lua54` | Script, C module loading, file writes and subprocess | NOT RUN |
| C37 | Go | `lang/go` | Offline module build, CGO program, HTTP service and temporary build cache | NOT RUN |
| C38 | Rust | `lang/rust` | Offline Cargo build/test, native linkage, subprocess and incremental cache | NOT RUN |
| C39 | OpenJDK | `java/openjdk21` | JIT, JNI library, threads, TLS, temporary files and service restart | NOT RUN |
| C40 | R | `math/R` | Pinned package/native extension install, numerical calculation and saved workspace | NOT RUN |

## Data services

| ID | Component | Candidate origin | Required exercise | Status |
| --- | --- | --- | --- | --- |
| C41 | PostgreSQL | `databases/postgresql17-server` | Initialize cluster, SQL transactions, concurrent clients, extension, backup/restore and crash recovery | NOT RUN |
| C42 | MariaDB | `databases/mariadb114-server` | Initialize data directory, transactions, socket/TCP, backup and restart persistence | NOT RUN |
| C43 | MySQL | `databases/mysql84-server` | Initialize data directory, authenticated transactions, plugin loading and restart persistence | NOT RUN |
| C44 | SQLite | `databases/sqlite3` | WAL, concurrent readers/writer, locks, backup and durable reopen | NOT RUN |
| C45 | Redis | `databases/redis` | Client operations, RDB/AOF persistence, restart and configured authentication | NOT RUN |
| C46 | Valkey | `databases/valkey` | Client operations, persistence, module loading where supported and restart | NOT RUN |
| C47 | Memcached | `databases/memcached` | Concurrent set/get, eviction, TCP/UNIX socket and intentional cache loss on restart | NOT RUN |
| C48 | MongoDB | `databases/mongodb80` | Authenticated CRUD, indexes, journal recovery and backup/restore | NOT RUN |
| C49 | RabbitMQ | `net/rabbitmq` | Publish/consume, durable queue, acknowledgement, restart and Erlang runtime | NOT RUN |
| C50 | Mosquitto | `net/mosquitto` | MQTT publish/subscribe, authentication, TLS, retained messages and restart | NOT RUN |

## Web and network services

| ID | Component | Candidate origin | Required exercise | Status |
| --- | --- | --- | --- | --- |
| C51 | nginx | `www/nginx` | Static and proxied HTTP/TLS, logs, worker privileges, reload and restart | NOT RUN |
| C52 | Apache HTTP Server | `www/apache24` | Static/PHP or CGI request, dynamic module, TLS, logs and graceful reload | NOT RUN |
| C53 | Caddy | `www/caddy` | Local TLS fixture, reverse proxy, writable certificate state and reload | NOT RUN |
| C54 | HAProxy | `net/haproxy` | TCP/HTTP proxy, health checks, stats socket, reload and connection handling | NOT RUN |
| C55 | lighttpd | `www/lighttpd` | Static/FastCGI requests, module loading, logs and restart | NOT RUN |
| C56 | Traefik | `net/traefik` | File-configured routing, local TLS, backend change and state persistence | NOT RUN |
| C57 | BIND | `dns/bind920` | Authoritative test zone, UDP/TCP queries, zone reload and journal writes | NOT RUN |
| C58 | Unbound | `dns/unbound` | Recursive fixture resolution, trust-anchor/cache state and reload | NOT RUN |
| C59 | dnsmasq | `dns/dnsmasq` | Isolated DNS/DHCP, lease persistence and unprivileged operation | NOT RUN |
| C60 | Kea | `net/kea` | Isolated DHCP lease allocation/renewal, configuration reload and lease database | NOT RUN |

## Identity and operations

| ID | Component | Candidate origin | Required exercise | Status |
| --- | --- | --- | --- | --- |
| C61 | Postfix | `mail/postfix` | Local-only SMTP, queued mail, delivery, aliases, queue permissions and restart | NOT RUN |
| C62 | Dovecot | `mail/dovecot` | IMAP authentication, mailbox/index writes, delivery and restart persistence | NOT RUN |
| C63 | Pure-FTPd | `ftp/pure-ftpd` | Authenticated local FTP/TLS upload/download, user isolation and permission denial | NOT RUN |
| C64 | Samba | `net/samba419` | SMB share, authentication, ACLs, locks, file transfer and reconnect | NOT RUN |
| C65 | OpenLDAP | `databases/openldap26-server` | Directory initialize, TLS bind/search/update, access denial and durable restart | NOT RUN |
| C66 | SSSD | `security/sssd2` | NSS/PAM against local directory fixture, cache writes and offline/failure behavior | NOT RUN |
| C67 | sudo | `security/sudo` | Allow/deny command policy, PAM, environment handling, timestamps and audit record | NOT RUN |
| C68 | doas | `security/doas` | Allow/deny elevation, PAM where configured, identity and environment handling | NOT RUN |
| C69 | rsync | `net/rsync` | Local and SSH transfer, permissions, links, incremental update and checksums | NOT RUN |
| C70 | Restic | `sysutils/restic` | Create local backup repository, backup, verify, restore and prune fixture data | NOT RUN |

## Developer and desktop tools

| ID | Component | Candidate origin | Required exercise | Status |
| --- | --- | --- | --- | --- |
| C71 | BorgBackup | `archivers/py-borgbackup` | Create repository, backup, deduplicate, verify, restore and prune fixture data | NOT RUN |
| C72 | Git | `devel/git` | Clone local repository, commit, hooks, SSH transport and checkout ownership | NOT RUN |
| C73 | CMake | `devel/cmake` | Configure/build/install sample project to ordinary prefix; shared-library discovery | NOT RUN |
| C74 | GNU Make | `devel/gmake` | Parallel compilation, subprocess environment and installation to ordinary prefix | NOT RUN |
| C75 | Ninja | `devel/ninja` | Parallel/incremental native build, depfiles and clean | NOT RUN |
| C76 | tmux | `sysutils/tmux` | PTY sessions, sockets, detach/attach, child shells and terminal resize | NOT RUN |
| C77 | Neovim | `editors/neovim` | Edit/save, swap/undo, plugin loading and external language-service subprocess | NOT RUN |
| C78 | Firefox | `www/firefox` | Real GUI launch, local HTTPS page, profile/cache, downloads and content processes | NOT RUN |
| C79 | Chromium | `www/chromium` | Real GUI launch, local HTTPS page, profile/cache, downloads and renderer sandbox | NOT RUN |
| C80 | FFmpeg | `multimedia/ffmpeg` | Decode/encode generated media, load codecs and verify output; hardware acceleration separate | NOT RUN |

## Relationship to existing gates

This matrix supplements [system-security.md](system-security.md). It does not
replace verified-boot tampering tests, MAC_ABAC/OpenES policy/event tests,
Capsule/SwitchBoard qualification, protected updater transactions, key rotation,
factory-key shim qualification or physical hardware tests. Those remain separate
mandatory gates. Extend this matrix as supported features grow; derive installed
file coverage from selected package inventories, never from this hand-selected
application test list.

References: [FreeBSD packages and ports](https://docs.freebsd.org/en/books/handbook/ports/),
[network services](https://docs.freebsd.org/en/books/handbook/network-servers/),
and [PAM](https://docs.freebsd.org/en/articles/pam/). These describe upstream
interfaces and packaging conventions; they do not prove 5BSD compatibility.

## Additional third-party candidates

These extend C31–C80 to exactly 100 candidates. Some are widely used libraries
or build tools rather than standalone applications. Popularity is not a ranking.
Dependencies do not count as tested merely because another row installs them.

| ID | Component | Candidate origin | Required exercise | Status |
| --- | --- | --- | --- | --- |
| C81 | Erlang | `lang/erlang` | OTP supervision, sockets, distribution on an isolated peer and crash dump directory | NOT RUN |
| C82 | Elixir | `lang/elixir` | Offline Mix build, BEAM application, release start and persistent state | NOT RUN |
| C83 | Haskell GHC | `lang/ghc` | Compile, FFI, threads and dynamic library loading | NOT RUN |
| C84 | OCaml | `lang/ocaml` | Native and bytecode compilation, C bindings and writable build output | NOT RUN |
| C85 | Julia | `lang/julia` | JIT, offline package environment, precompile cache and numerical workload | NOT RUN |
| C86 | LuaJIT | `lang/luajit` | JIT and FFI, executable mappings and module discovery | NOT RUN |
| C87 | Tcl | `lang/tcl86` | Load native extension, event loop, sockets and subprocess | NOT RUN |
| C88 | Mono | `lang/mono` | Managed executable, JIT, native interoperability and writable user state | NOT RUN |
| C89 | Zig | `lang/zig` | Offline compile/test, C linkage, cache and installed executable | NOT RUN |
| C90 | GCC | `lang/gcc14` | C/C++ build, shared libraries, threads and runtime library lookup | NOT RUN |
| C91 | LLVM/Clang | `devel/llvm19` | C/C++ build, linker, sanitizers where supported and shared objects | NOT RUN |
| C92 | GDB | `devel/gdb` | Debug owned ordinary child, attach policy, core files; protected target rejection | NOT RUN |
| C93 | Meson | `devel/meson` | Configure/build/test/install, dependency detection and staged prefix | NOT RUN |
| C94 | Autoconf | `devel/autoconf` | Generate configure, feature probes and out-of-tree build | NOT RUN |
| C95 | Automake | `devel/automake` | Generate build, dependency tracking, distcheck and install staging | NOT RUN |
| C96 | Libtool | `devel/libtool` | Build/load shared library, install relink and uninstalled build execution | NOT RUN |
| C97 | pkgconf | `devel/pkgconf` | Custom prefix lookup, dependency closure and cross sysroot isolation | NOT RUN |
| C98 | ccache | `devel/ccache` | Cache hit/miss, concurrent builds and cache permission isolation | NOT RUN |
| C99 | pytest | `devel/py-pytest` | Temporary directories, subprocess capture, plugins and failing-test reporting | NOT RUN |
| C100 | NumPy | `math/py-numpy` | Native extension, BLAS threads, mmap arrays and numerical result | NOT RUN |
| C101 | SciPy | `science/py-scipy` | Compiled extensions, linear algebra, sparse solver and temporary files | NOT RUN |
| C102 | pandas | `math/py-pandas` | CSV/SQL import/export, timezone data, native extension and durable output | NOT RUN |
| C103 | SymPy | `math/py-sympy` | Symbolic calculation, generated code and ordinary user cache | NOT RUN |
| C104 | Django | `www/py-django52` | WSGI/ASGI request, migration, static files, sessions and database writes | NOT RUN |
| C105 | Flask | `www/py-flask` | HTTP routing, upload, sessions, subprocess workers and error logs | NOT RUN |
| C106 | FastAPI | `www/py-fastapi` | ASGI request, validation, async database access and graceful shutdown | NOT RUN |
| C107 | Gunicorn | `www/py-gunicorn` | Worker fork, UNIX socket, logs, privilege drop and graceful reload | NOT RUN |
| C108 | Uvicorn | `www/py-uvicorn` | Async requests, WebSocket, worker shutdown and TLS fixture | NOT RUN |
| C109 | aiohttp | `www/py-aiohttp` | Async client/server, DNS, TLS, streaming and connection cleanup | NOT RUN |
| C110 | Psycopg | `databases/py-psycopg` | PostgreSQL TLS/socket connection, transactions, binary data and error recovery | NOT RUN |
| C111 | SQLAlchemy | `databases/py-sqlalchemy20` | Connection pool, transactions, schema creation and reconnect | NOT RUN |
| C112 | curl | `ftp/curl` | HTTP/TLS, proxy, CA bundle, client certificate and download checksums | NOT RUN |
| C113 | wget | `ftp/wget` | TLS download, resume, proxy and output permissions | NOT RUN |
| C114 | lftp | `ftp/lftp` | SFTP/FTP fixture transfer, mirror, resume and credential permissions | NOT RUN |
| C115 | Bash | `shells/bash` | Login/non-login shells, startup files, job control, redirections and process substitution | NOT RUN |
| C116 | Zsh | `shells/zsh` | PTY job control, completion cache, startup files and descriptor substitution | NOT RUN |
| C117 | Fish | `shells/fish` | Interactive PTY, history, completion and child execution | NOT RUN |
| C118 | Vim | `editors/vim` | Edit/save, swap recovery, plugins, subprocess and terminal operation | NOT RUN |
| C119 | Emacs | `editors/emacs` | GUI and terminal, file lock/autosave, native modules and subprocess | NOT RUN |
| C120 | RRDtool | `databases/rrdtool` | Create/update/fetch, graph output, permissions and retained database | NOT RUN |
| C121 | Prometheus | `net-mgmt/prometheus2` | Local target scrape, query, TSDB WAL, restart and retention | NOT RUN |
| C122 | Grafana | `www/grafana` | HTTP login, datasource query, plugins, database state and restart | NOT RUN |
| C123 | OpenVPN | `security/openvpn` | TUN creation, isolated TLS peers, routing, privilege drop and reconnect | NOT RUN |
| C124 | WireGuard tools | `net/wireguard-tools` | Supported kernel interface, isolated peers, routing, key handling and teardown | NOT RUN |
| C125 | socat | `net/socat` | TCP/UNIX sockets, PTYs, descriptor passing where supported and EOF handling | NOT RUN |
| C126 | rclone | `net/rclone` | Pinned local SFTP backend, copy/sync, checksum and config permissions; FUSE separately | NOT RUN |
| C127 | 7-Zip | `archivers/7-zip` | Archive/extract, encryption, Unicode paths and malformed archive rejection | NOT RUN |
| C128 | Zstandard | `archivers/zstd` | Streaming and multithreaded compression, dictionary use and corruption detection | NOT RUN |
| C129 | ImageMagick | `graphics/ImageMagick7` | Image conversion, delegates, security policy, temp files and resource limits | NOT RUN |
| C130 | Xorg | `x11/xorg` | Real display, input, ordinary client, shared memory and clean session teardown | NOT RUN |

## Complete base coverage: inventory, not a fixed shortlist

“All base” means every shipped object and public interface in the supported
build profiles, including optional components, libraries, kernel modules,
boot programs, scripts, rc hooks, configuration, generated state and aliases.
It does not mean attempting every combinatorial arrangement of every flag.

For each selected generation:

1. Consume its package payload inventory and retain package ownership, object
   type, permissions, links, hashes and configuration declarations. Include
   dependencies and hardware packages. Do not infer coverage from executable
   permission bits alone: libraries, interpreted scripts and links also matter.
2. Reconcile against the installed image and generated-file manifest. Associate
   each object with a test family and each callable interface with an exercise.
   Documentation/data can be covered by installation/readability/consumer tests;
   an executable cannot be covered merely by a package installation test.
3. Compare evaluated build/install manifests across supported architectures and
   WITH/WITHOUT profiles with published package inventories. Record omitted
   optional features, packaging omissions and intentionally unsupported items
   separately. Source Makefile text is a discovery aid, not an evaluated graph.
4. Include every rc script and capability unit, even when disabled by default.
   Resolve every unit's program, helpers, libraries, policy, writable state and
   package owner. Enumerate endpoints/methods from unit declarations and protocol
   schemas. New units, endpoints and unassigned files reopen coverage review.
5. Record the tested command/options, principal, expected effects, state paths,
   dependencies, positive and negative controls and actual evidence. Until an
   object has an assigned exercise or justified data-only coverage it remains
   UNASSIGNED; it cannot disappear from the denominator or silently pass.

The 2026-10-23 snapshot contains **521 selected packages and 35,061 unique
objects** (19,032 regular files, 13,343 hardlinks, 1,230 symlinks and 1,456
directories). A preliminary program/alias scan yields 1,528 candidates; it is
not a completeness proof. The full object list retains everything the heuristic
misses. The source scan also retains 3,120 Makefile declarations requiring
build-graph review. The selected generation is not every possible base build.

Review artifacts are in the `compatibility-expanded-20261023` review set:
`all-installed-objects.tsv`, `installed-programs-and-aliases.json`,
`source-build-declarations.json`, and `review.json`. These are dated planning
artifacts, not a runtime protection allowlist or an authenticated inventory.
The input inventory hash is recorded in `review.json`; its reader explicitly
reports that authentication is not performed by that reader. Regenerate from
the next selected generation; do not copy this snapshot forward as coverage.

### Base families and common/problematic operations

Each family requires individual entries for its actual shipped programs,
aliases and options. The names below guide assignment; they do not waive
coverage of unnamed package objects. All families are **NOT RUN** under this
integrated contract. Features absent from a particular build need another
supported profile or a documented UNSUPPORTED result.

| Family | Programs/interfaces to include | Required options and edge cases |
| --- | --- | --- |
| Boot and init | firmware, loaders, kernel, init, rc, service, sysrc | Conventional/hardened boot; single-user/recovery; console; dependency failure; read-only root; clean reboot/poweroff |
| Shells | sh, csh and shipped alternatives | Interactive/login/noninteractive; job control; pipes; here-docs; redirection; `/dev/stdin`; traps; startup files |
| Core file tools | cp, mv, rm, ln, mkdir, install, touch, truncate | Recursive/preserve/link modes; cross-filesystem moves; atomic replacement; sparse files; ACLs; protected destination denial |
| Search/text | find, xargs, grep, sed, awk, sort, join, cut, tr, uniq, diff, patch | NUL names; large input; locale; temporary files; parallel children; in-place edits; malformed input |
| Inspection | ls, stat, file, readlink, realpath, du, df, getconf | ACL/flags; symlink loops; inaccessible files; mounted datasets; aliases |
| Archives/compression | tar, cpio, pax, gzip, bzip2, xz and shipped codecs | Streams; ownership; hardlinks; xattrs; sparse files; traversal rejection; interrupted extraction |
| Checksums/encoding | sha256 and hash aliases, cksum, base64, uuencode/uudecode | Standard input; binary data; verification failure; output permissions |
| Accounts | login, getty, su, passwd, pw, adduser, chpass, vipw, pwd_mkdb, cap_mkdb | Root/non-root; invalid credentials; locked/expired accounts; groups; concurrent database updates; interrupted writes |
| PAM | Every installed pam_*.so and shipped service stack | auth/account/password/session; required/requisite/sufficient/optional; conversation; expiry; session cleanup; missing backend |
| NSS | nsswitch, getent, nscd, libc account/group/host lookups | files/directory/cache; supplemental groups; negative caching; backend outage; service identity before/after privilege drop |
| Login records | last, lastlogin, who, w, users, utx tools | Concurrent logins; logout/crash; writable records; accounting and privacy |
| SSH server | sshd and helper executables | Key/password/PAM; Match; privilege separation; AuthorizedKeysCommand; chroot SFTP; forwarding; revocation; rekey; reload |
| SSH clients | ssh, ssh-agent, ssh-add, ssh-keygen, ssh-keyscan, scp, sftp | Pinned host keys; agent sockets; ProxyJump; certificates; transfer resume; denied forwarding; legacy SCP only if supported |
| TLS/crypto | openssl, certctl, trust stores, libcrypto/libssl | CA update; TLS client/server; key permissions; providers/engines if supported; random seeding; bad certificate denial |
| Logging | syslogd, logger, newsyslog, logctl, BSDLog | Local/remote sockets; jail sockets; rotation and reopen; permissions; full disk; service restart; no lost boundary records |
| Scheduling | cron, crontab, at, atrun, batch, periodic | User/system jobs; PATH/HOME; mail output; allow/deny files; spool permissions; cancellation; reboot persistence |
| Process control | daemon, kill, pkill, pgrep, nice, renice, timeout, procstat, ps, top | Ordinary/protected targets; PID/group; SIGIO/SIGURG; exited owners; privilege drop; rlimits; restart loops |
| Debug/profiling | gdb if shipped, lldb, ktrace, kdump, truss, DTrace, pmc tools, gcore | Owned ordinary process; protected target denial; core destination; tracing permissions; no privileged data leakage |
| Time/locale | date, adjkerntz, ntpd/ntpq, tzsetup, zic, zdump, locale, iconv | Fixture time peer; drift state; timezone changes; DST; leap handling; conversions; invalid sequences |
| DNS/resolver | local_unbound, unbound tools, resolvconf, host/drill if shipped | TCP/UDP; DNSSEC; resolver update; outage; anchors; caches; local zone reload |
| Network configuration | ifconfig, route, netstat, arp, ndp, setfib, routing daemons | IPv4/IPv6; FIBs; interface rename/create/destroy; multicast; route change; ordinary/protected boundaries |
| Network clients | ping, ping6 aliases, traceroute, fetch, ftp, nc, sockstat | Raw-socket permissions; TCP/UDP; TLS trust; proxies; IPv6; DNS failure; UNIX sockets |
| DHCP/IPv6 autoconfiguration | dhclient, rtsold, rtadvd and hooks | Renewal; lease persistence; link loss; resolver updates; isolated RA/DHCP peer |
| Firewalls | pfctl, ipfw, ipf when built, ftp/tftp proxies, blacklist/blocklist tools | Load/reload; state; NAT; anchors/tables; IPv6; counters; reject unauthorized changes |
| NFS | mount_nfs, nfsd, mountd, nfsuserd, nfscbd, nfs tools | v3/v4; root mapping; read-only/read-write exports; reconnect; protected objects; UID/GID mapping |
| RPC/NFS security | rpcbind, rpc.lockd, rpc.statd, gssd, rpc.tlsclntd/rpc.tlsservd | Lock contention/recovery; TLS; Kerberos if built; principal failures; daemon restart |
| Autofs and mounts | automount, automountd, autounmountd, mount/umount and every shipped mount helper | Network outage; busy mounts; remount; nullfs; tmpfs; unionfs if supported; read-only backing protection |
| UFS and recovery | newfs, fsck variants, tunefs, dump, restore, quotacheck, quota tools | Disposable disks; dirty recovery; ACL/quota; backup/restore; low space; immutable base denied |
| ZFS | zpool, zfs, zdb, bectl/libbe | Dataset/snapshot/clone; send/receive; mountpoint/canmount; pool import/export; encrypted datasets if supported; active-generation protection |
| Disk management | geom/gpart/glabel/geli/gmirror/gstripe/graid families | Scratch devices; partition change; encryption keys; provider disappearance; backing-store tamper denial |
| Storage services | ctld, ctladm, iscsid, iscsictl, camcontrol and CAM tools | Isolated initiator/target; reconnect; reservations; volume permissions; protected backing devices |
| Jails | jail, jexec, jls, jail.conf, libjail | Ordinary writable root; shared network/VNET; devfs; mounts; package install; teardown; namespace escape negatives |
| Virtualization | bhyve, bhyvectl, bhyveload, virtiofsd, vm tools | Supported nested/physical fixture; disks; tap/vsock; shared directories; crash cleanup; no QEMU substitution for unsupported hardware |
| Device services | devd, devctl, devinfo, devfs, kld tools | Hotplug; events; rules; permissions; authorized module load; rejected unsigned/tampered module; restart |
| Hardware administration | pci/usb/acpi/gpio/i2c/spi/cpu/nvme/storage utility families | Safe query; disposable/physical fixtures for mutation; unsupported device explicit; never host mutation |
| Terminals/input | stty, tset, resizewin, script, vidcontrol, kbdcontrol, moused | PTY creation; modes; SIGWINCH; serial console; redirected streams; GUI/physical input separate |
| Audio | mixer, sndctl, virtual_oss, supported sound helpers | Playback/capture; device permissions; shared clients; hotplug; physical loopback separate |
| Wireless/Bluetooth | wpa_supplicant, wpa_cli, hostapd, Bluetooth legacy tools and providers | Keys/state; connect/reconnect; scan; paired-device persistence; hardware access; isolated radio lab |
| Power | powerd, acpiconf, shutdown, reboot, halt, watchdogd, watchdog | Ordinary authorization; protected policy; suspend/resume on hardware; watchdog recovery; last operation in fixture |
| Mail | mail, mailwrapper, dma/sendmail where built, aliases tools | Local delivery; queue; aliases; permissions; TLS fixture; restart; spool persistence; no public relay |
| Printing | lpr/lpd/lpq/lprm, printcap and filters | Submit/cancel; spool; filter subprocess; remote fixture; ownership and failures |
| Directory/legacy services | NIS/YP suite, inetd, rarpd, bootpd, tftpd, fingerd, talkd, rwhod if built | Isolated activation; writable maps/spools; malformed input; explicit disabled-default policy; optional profile coverage |
| SNMP/monitoring | bsnmpd, sysctl, iostat, vmstat, systat, exporters | Query and permitted mutation; authentication; MIB modules; reload; ordinary observability |
| Audit/MAC | auditd, audit tools, set/getfmac, set/getpmac, mac_abac_ctl/mac_abacd, OpenES | Allow/deny rules; root subject; subject/target context; event actor; restart; overflow/failure policy; ABAC lock safety |
| Capability management | Capsule, SwitchBoard, capsulectl, switchboardctl, policyctl | Full provider matrix below; normal packaged startup; admission; ordinary child behavior; no blanket authority grant |
| Signing/integrity | capsign, veriexec tools, uefisign, loader checks | Valid/invalid/expired or revoked inputs as supported; code versus release trust; tamper; unsigned ordinary apps under owner policy |
| Package/update lifecycle | pkg bootstrap and full pkg, build-bsd, etcupdate, freebsd-update when built | Install/scripts/config merge; inactive generation; selection/confirmation/rollback/retirement; legacy updater must not modify protected live base |
| Build toolchain | make, cc/c++, ld, ar, nm, ranlib, strip, objcopy, objdump, yacc, lex, rpcgen, config | Native/shared/static builds; temporary/object directories; headers; compiler runtime; production world/kernel/package path |
| Installation/media | bsdinstall, bsdconfig, makefs, mkimg, mdconfig, efibootmgr | Disposable target; metadata; signed boot media; separate base/hardware publication; no host boot-variable mutation |
| Rescue | rescue multicall entries, fsck/mount recovery tools | Each alias invocation; dependency independence; recovery access; integrity-preserving repair or new generation |
| Runtime linking | rtld, ldconfig, libmap, every installed shared library | Writable third-party libraries/plugins; runpaths; TLS; preload for ordinary apps; protected-process injection denial |
| libc/kernel ABI | libc, libthr, libutil, libm, libexec helpers | fork/exec/spawn; threads; signals; kqueue; mmap/mprotect; shared memory; sockets; sendfile; locks; locale; entropy |
| Filesystem metadata | chmod/chown/chflags, ACL/xattr tools, mtree | Owner/groups; ACL inheritance; flags; links; paths with spaces/Unicode; symlink races; protected replacement denial |
| Documentation/data | man, mandoc, apropos, makewhatis, terminfo, zoneinfo, certificates | Readability; indexes/caches in intended writable locations; compression; package ownership; consumer correctness |
| Tests and optional profiles | ATF/kyua, installed test helpers, optional ABI/architecture packages | Package all required helpers; enumerate real tests; record skips; feature-specific builds; no passing an absent feature |

### Option coverage rules

For every program, review its installed manual and existing tests. Record:
default/common invocation; flags that change output/state location; privilege
changes, jail/chroot and daemonization; plugins/preloads; remote access;
configuration reload; resource limits; uncommon flags touching protected files,
raw devices, mounts, identities or policy. Expand interacting combinations when
one changes another's authorization or storage behavior. Preserve the exact
supported options instead of inventing flags shared by similarly named tools.

Run as an ordinary user, administrative root, and explicitly authorized service
where applicable. Check success in writable locations and denial at protected
boundaries. Include full/readonly disk, inaccessible state, missing dependency,
backend outage, concurrent access, crash/restart and retained-data upgrades.
Hardware-only and destructive operations need appropriate disposable fixtures;
query-only tests do not qualify write/control functionality.

## Every capability daemon and its helpers

All rows are **NOT RUN**. The current package inventory contains the providers
listed below. Most live under `/Capabilities/System/*/Units/*/bin`, while
SwitchBoard is `/usr/libexec/switchboard` and Capsule is `/usr/sbin/capsule`.
Do not discover providers solely by scanning `/usr/sbin` or `capbundle/`:
Bluetooth units also live elsewhere in their source directories.

| Provider/manager | Required operation-specific exercises |
| --- | --- |
| Capsule | Kernel bootstrap handshake; owner configuration; manager launch; admission/denial; normal UNIX descendants; policy validation; recovery/shutdown |
| SwitchBoard | Boot/on-demand/calendar activation as supported; identities/NSS; dependency ordering; registry changes; reconnect; session revocation; crash/restart throttling; management authorization |
| BSDAudit | Authorized record submission; validated identity; record ordering; durable sink/restart; backpressure and rejected malformed records |
| BSDCrypto | Each schema operation; key/descriptor rights; known-answer result; denied algorithm/key access; resource cleanup; provider restart |
| BSDDevice | Permitted device opens with limited rights; wrong device/mode denial; hotplug/removal; stale handles; ordinary devd coexistence |
| BSDExtension | Authorized module load/unload; dependencies; failed initialization; tampered/unauthorized modules; extension disappearance |
| BSDFilesystem | Each endpoint; read-only resources and writable service state; create/read/rename/fsync; confinement; revoked/stale descriptor; restart; actual storage persistence |
| BSDLog | Client write, record identity, query if supported, rotation/reopen; volume limits; restart; ordinary syslog coexistence |
| BSDMemory | Memory pressure notifications; reclaim coordination; protected-service policy; stalled/dead consumers; bounded memory; no arbitrary service killing |
| BSDNamespace | Create/enter/destroy namespace through supported protocol; root descriptor; rights; repeated cleanup; denied namespace escape |
| BSDNetwork | Network/Admin/PF/State endpoints individually; bind/connect/listen/accept; DNS; rights transfer; firewall and observation authorization; IPv6; disconnect |
| BSDNotify | Public and system endpoints separately; subscribe/publish; namespace isolation; rejected system sender; overflow; subscriber death |
| BSDPower | Permitted query/control; unauthorized power action denial; request audit; shutdown/reboot fixture; suspend on capable hardware |
| BSDSysctl | Read and authorized write; type/length validation; protected sysctl denial; stale policy and concurrent clients |
| BSDTime | Query, authorized step/slew; malformed/out-of-range request; unauthorized setter; ordinary time-service coexistence |
| BSDTrace | Authorized trace session; target scoping; unauthorized client/target; buffer pressure; consumer death; complete teardown |
| BSDVM | Implemented vsock operations, rights and peer isolation; failed connection; endpoint lifetime; no claim of full VM management from a vsock-only test |
| BSDBluetooth | Discovery, pairing/bond persistence, GATT operations and notifications; denied clients; disconnect/reconnect; physical radio qualification |
| BSDBluetoothController | Controller handoff, descriptor limits, initialization/reset, helper death/restart and device removal; physical-controller coverage |
| mac_abacd and mac_abac_ctl | Policy loading/admin boundary, reload failures, audit; allow/deny with UID/group/context; process debug/sched/signal/wait; root remains subject to mandatory BIP |
| OpenES broker and oeslogger | Actual broker host/helper ownership; registration; supported AUTH/NOTIFY separately; event/actor attribution; backlog, disconnect, timeout and configured failure mode |

The last two rows are security integrations, not claims that each is a separate
capability-provider executable. Bind the broker to its actual implementation.
Also test every shipped control client, including capsulectl, switchboardctl,
networkcmpctl, sysctlcmpctl, BSDPowerctl, BSDTimectl, logctl, notifyctl,
tracectl and sysextctl, plus identity/NSS helpers, Bluetooth helpers, and
provider-linked libraries. Client success cannot replace provider negative
authorization tests.

**Common provider contract:** derive every endpoint and method from the selected
unit/schema; test authorized and unauthorized clients, ordinary unsigned clients
where allowed, malformed requests, descriptor rights, reconnect and cancellation,
parallel callers, resource exhaustion, clean shutdown and crash recovery. Verify
lease/session revocation only where the policy actually requires it; do not invent
leases for system providers. Exercise dependency failure and writable-state access
under the actual packaged policy. Capture ordinary and protected actor attribution
in ABAC/OpenES. Test generation upgrade with existing state; never treat state
rollback as automatically safe. No test-only privileged replacement daemon or
weakened admission policy may qualify the production artifact.

## Packaging gaps and possible base reductions

**Confirmed:** this selected inventory already owns the capability providers,
Capsule, SwitchBoard, mac_abacd and oeslogger. Some providers share `runtime`;
shared package ownership is not an absence from pkgbase. The full `pkg` package
is a selected dependency in addition to the base bootstrap. Ownership alone does
not prove complete helper, configuration or mutable-state packaging.

**Still to audit:** compare the completed world/install METALOG and every
supported option profile against base plus hardware package payloads. Review
unowned generated files, service identities, configuration defaults, PAM/NSS
modules, helper executables, units, policy/schema files, test peers and required
firmware. A missing selected package is a selection issue; an installed build
output absent from all appropriate package manifests is a packaging defect.
Runtime-created sockets, leases and database contents need declared storage and
ownership/lifecycle policy, not packaging of live data. Do not move arbitrary
third-party applications into base to evade compatibility failures.

**Review candidates, not approved removals:** optional legacy NIS/YP, finger,
talk/rwho, old boot/RPC helpers, and duplicate service implementations deserve a
usage/security/maintenance review. The source tree contains such components;
that does not mean they are enabled or installed in the selected image. Several
corresponding executables are absent from this snapshot. Consider optional
packages or disabled defaults before removal, preserve supported workflows and
migration documentation, and test remaining consumers. Age alone is not evidence
that a tool should be removed. Existing ordinary UNIX services must not be
removed merely because a capability provider now exists.

Legacy live-base updaters need an explicit mode policy: conventional systems can
retain their supported update behavior; hardened systems require an authenticated
new-generation path or a clear refusal. Do not silently bypass immutable-base
protection to make an old updater pass.

No additional move into pkgbase or removal from base is justified solely by this
inventory review. Report concrete unowned outputs or broken dependencies before
proposing such changes. The packaging/profile reconciliation remains open.

## Integration and completion tracking

This change expands documentation and records a read-only inventory snapshot.
It changes no build input, signing policy, package selection or VM runner, so no
`build-bsd.c` or backend change is needed for this planning update. A future
executable qualification runner must use the maintained build-bsd generation and
evidence paths, accept inventories/configuration as inputs, and reject unassigned
coverage; it must not become an alternate image assembler or a hardcoded list of
files deemed protected. The inventory-to-test coverage gate is **planned, not
implemented**. Existing component tests remain useful but do not mark these rows
PASS without the specified integrated evidence.
