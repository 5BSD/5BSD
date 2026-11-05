# Native secure production composition (2026-11-05)

## Source-owned producers and parents

//secure:production_installation_archives now composes the lib, libexec,
usr.bin and usr.sbin parents and the optional CA-root contribution. They retain
original OpenSSL/OpenSSH/USB/CA-root selections. OpenSSL gains five component
archive endpoints for its existing core, engines, modules, SSL and CLI manifests.
The libcrypto parent preserves its engines/modules recursion. These endpoints
reuse existing compilation, generation, link, debug and metadata producers;
they do not rebuild an alternative OpenSSL or omit provider/engine payloads.

//secure:production_products also requests both internal libpkgecc archives.
That original INTERNALLIB remains a build-only contribution, including at the
standalone secure parent when OpenSSL is disabled. It is not installed as a
public library. SSH archive visibility now admits only each macro caller's
immediate owning parent; the three standalone archive declarations have the
same explicit parent access.

The complete selected profile has 21 installation archives (63 typed archive/
request/directory outputs) and two internal library archives. This is AMD64
production composition. Full installed tests, other ABIs and unsupported Heimdal
consumer contexts remain open/gated; no complete world claim follows.

## Certificate inventory and original comparison

Trusted and untrusted source directories each declare glob(["*.pem"]), matching
the maintained Make selection. Every matching source file is an explicit native
installation input with its original category/path; no hand-selected certificate
list or build-time fetch is used. Normal builds do not update certificate sources
or the host trust store. This glob is source inventory, not runtime discovery.

Full original comparison caught two omitted directory records. Their original
package is utilities; the files belong to caroot. The corrected native manifests
preserve root/wheel 0755 directories and root/wheel 0444 certificate files.

Evidence under /usr/obj/usr/src:

- bazel-secure-caroot-make-r3-20261105 is the complete independent original Make
  reference. The initial explicit CAROOT override was rejected because this
  data-only Makefile does not query that option; the final direct component
  invocation uses the unchanged recorded SDK profile, without weakening the
  reference guard or fetching certificate material. r2 predates the final
  native directory declarations and is superseded for source bindings.
- bazel-secure-parent-native-r2-20261105/caroot-original-review.json verifies
  all 169 original component records: 120 trusted and 47 untrusted certificate
  files plus both category directories. Complete inventory, type/owner/group/
  mode/tags, archive metadata and every certificate byte match. This establishes
  source/install parity, not certificate trustworthiness or initialized runtime
  trust-store hash links.
- The final expanded r3 parent-review.json binds the identical certificate
  archive to that comparison and verifies all 86 production output entries
  unchanged from r2. These are logical capture entries across both endpoints,
  not 86 unique files or installation archives.

## Build and bounded runtime evidence

- bazel-secure-parent-native-r1/r2-20261105 pass through normal build-bsd with
  sixteen jobs. Seven selected test targets pass: crypto static/shared smoke,
  TLS static/shared, legacy-provider/engine loading, archive contracts and
  frontend source settings. r1 omits the two original certificate directories
  and is superseded by r2 for complete CA metadata.
- bazel-secure-parent-native-r3-20261105 passes all twelve selected test targets,
  adding the three SSH daemon version/effective/invalid configuration cases
  and two direct SFTP transfer/read-only cases. Its immutable capture contains
  the unchanged 21 production archives and both internal archives.
- Crypto smoke tests exercise digest, AEAD known answers and rejection, random,
  bignum and signature operations. TLS tests use in-memory BIO pairs for TLS
  1.2/1.3 handshake/data exchange, untrusted peers and hostname rejection.
  Their generated fixture certificate is local test data; it never substitutes
  for CA inventory, update signing, bundle signing or verified-boot inputs.
- SFTP tests use declared native client/server executables with direct pipes,
  transferring and checking a temporary payload and rejecting writes in read-only
  mode. SSH configuration tests generate only a scratch host key and invoke
  version/configuration modes. They start no listener and authenticate no host
  user. These are useful protocol/parser checks, not SSH login/PAM acceptance.
- The existing module-load test loads legacy and engine modules; it does not
  qualify FIPS runtime/configuration. Full cryptographic certification, complete
  OpenSSL/SSH regression suites and installed-test closure are not established
  by seven or twelve reported target results.
- bazel-secure-selection-r1-20261105/review.json compares actual configured
  native parent labels against original Make recursion for six profiles. The
  sum of immediate-owner counts across root and its four subparents is 24
  default, six without OpenSSL, nine without OpenSSH, 23 without USB, 23 without
  CA roots and six without crypt. Nested roots/owners are counted at their own
  recursion levels; these numbers are not programs or installed-payload counts.
  Selection analysis is not alternative-profile compilation or runtime proof.

- bazel-secure-no-openssl-native-r1-20261105 passes an actual OpenSSL-disabled
  parent build with the frontend settings test. Its disabled-profile-review.json
  verifies only the unchanged CA installation archive and both internal pkg
  archives are produced. Crypto/SSH tests are not separately requested in this
  disabled profile and do not pull disabled software into the parent closure.
- bazel-secure-tests-enabled-rejection-r1-20261105 rejects the explicitly
  requested production_products target through its incompatible complete-test
  installation dependency. It does not silently accept a production-only subset
  for a full installed-tests request.

## Frontend and outstanding qualification

Existing build-bsd format-5 label/settings support carries the new parents and
component endpoints. The maintained manual is updated; no C dispatcher, schema,
signing, publication or replacement frontend is required.

Complete original OpenSSL/SSH component and whole secure installation metadata/
payload/debug/pkgbase reconciliation, test installations, alternate profiles/
ABIs, SSH login/PAM/credentials, boot trust-store initialization and FIPS runtime
remain open. Other world roots, complete world/kernel/module/pkgbase, independent
reproducible bootstrap, separate hardware/verified combined publication, VM and
controlled CPU/RAM/disk I/O/footprint/cache/sandbox acceptance remain required.
Make stays production/default. BIP is excluded. No host installation, upgrade,
trust-store update, publication or reboot is performed.
