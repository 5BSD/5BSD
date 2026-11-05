# Native NIS administration checkpoint (2026-11-05)

## Implementation

The source-owned usr.sbin production parent now includes all ten optional NIS
owners: ypbind, yp_mkdb, yppoll, yppush, ypset, ypserv, rpc.ypxfrd,
rpc.yppasswdd, rpc.ypupdated and ypldap. These targets retain original sources,
RPC generator modes, server-state sed transformations, parser/header generation,
local defines, shared dependencies, helper scripts, manuals and package=yp
installation metadata. ypserv installs its original variable-data Makefile and
relative symlink with Make's actual 0755 symlink request mode. This adds ten
archives to the selected administration profile, not ten new service-runtime
qualifications. Installed tests, sendmail and other ABIs remain gated.

Generators use declared rpcgen, cpp, sed and yacc tools and explicit outputs.
The generic bsd_filter action is shared with the existing fixture rule alias;
production RPC generation does not load a test rule. One actual database test
is added in Python; no Python compilation or dependency-discovery replacement
for native Bazel was introduced.

The configured native libc ABI is selected at optional RPC/wrapper boundaries.
A cc_import depends on the actual source-built libc DSO; its public interface
adds libc_nonshared without exporting libc's implementation link context. An
earlier candidate leaked a direct libsys dependency into yp_mkdb and was rejected
by strict original ELF comparison. The corrected candidate matches Make's
ordered libc-only dependency. Existing legacy shared_link_interface consumers
still need separate migration and original ELF qualification.

## Evidence under /usr/obj/usr/src

- bazel-nis-admin-native-r12-20261105: final normal build-bsd bazel-test run
  passes with 16 jobs. Administration installation has 1089 typed outputs
  (363 archive/request/directory triples); production_programs has 365 default
  outputs (363 installation archives and two printing internal archives).
  The request also builds usr.bin, libexec and SSH boundary consumers. These
  counts are scoped to this profile, not full-world completeness.
- All five requested test targets pass: source settings, libc runtime, ypcat
  aliases, ypmatch aliases and yp_mkdb roundtrip. Cached results are retained.
  The corrected-ABI focused bazel-nis-abi-native-r1-20261105 freshly executes
  the database test, whose three unittest cases cover payload/metadata, private
  file mode, exclusive creation, duplicate keys, continuation and filtering.
  It uses declared native runtime libraries and TEST_TMPDIR, without host
  domain mutation, RPC clear or service access.
- bazel-nis-admin-selection-r1-20261105/review.json: selection reconciliation
  accounts for all 256 immediate original Make administration owners in this
  selected profile. Selection is not complete linked/install/runtime parity.
- bazel-nis-admin-native-r10-20261105/original-program-review/review.json:
  complete original component metadata/data and strict ELF/debug comparisons
  pass for yp_mkdb, rpc.ypupdated and rpc.ypxfrd. Ordered dependencies,
  interfaces, hardening and both debug CRCs are checked; full binary/debug
  byte identity is not claimed. The final r12 final-review/review.json binds
  hash-identical captured archives to those reviews.
- bazel-nis-ypldap-parser-make-r1-20261105: original Make generation with
  actual YFLAGS=-d passes. The final native parse.h matches exactly; parse.c
  has 73 line replacements, solely #line source/output paths. Raw differences
  and exact original/native lines are retained in r12 final-review. This is
  generation evidence, not full ypldap executable parity.
- bazel-nis-admin-disabled-native-r2-20261105 passes. Its
  default-regression-review.json hash-verifies 1415 captured output entries
  against bazel-printing-native-r3-20261105: 1413 identical; two entries name
  the same changed bsd-build archive. Complete archive member metadata is
  unchanged; only usr/share/man/man8/bsd-build.8.gz payload differs.

## Remaining acceptance

Seven NIS programs still need complete original linked/install/debug comparison.
The bootstrap SDK profile disables NIS; the original ypbind reference fails
linking absent YP symbols. A matching independently built reference ABI is
required, without mutating or silently substituting the verified SDK. Native
construction and existing libc tests do not close this reference gap.

Live binding, map transfer, update/password authorization, LDAP synchronization,
service lifecycle, SSH/authentication and audit/probe delivery remain untested
here. Other configurations/architectures, installed tests, complete world,
bootstrap independence/reproducibility, pkgbase and hardware/combined repository
publication, VM and controlled CPU/RAM/disk I/O/footprint/cache/sandbox acceptance
remain required. Earlier recursive Make references also need configuration
coverage refresh after the installconfig recursion correction.

## Frontend scope

Existing format-5 targets/settings carry this change through normal build-bsd.
The maintained manual is updated and captured by final qualification; no C
dispatcher, schema, signing or publication contract change is needed. Bundle
signing, verified boot and protection against compromised root are distinct;
these unsigned build checks establish none of those security guarantees. Make
remains production/default; BIP remains excluded. No host installation, upgrade,
publication or reboot is performed.

## Eight-family runtime integration follow-up

Actual combined tests expose SDK libc in SSH's runtime declarations, despite
the selected native NIS program ABI. The declared NIS runtime now supplies
native libc/libsys, preserving the original explicit SDK pair for defaults.
Test bodies and expectations are unchanged. The combined 34-target test run
and final immutable capture pass; default secure production outputs remain
unchanged. See EIGHT-FAMILY-COMPOSITION-QUALIFICATION.md. Live NIS service and
original linked/whole-world gates above remain open.
