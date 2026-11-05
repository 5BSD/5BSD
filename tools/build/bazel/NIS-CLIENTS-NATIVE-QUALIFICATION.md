# Native optional NIS clients (2026-11-04)

The AMD64 ypcat, ypmatch and ypwhich programs now have source-owned native
construction, original yp package ownership, split debug/manual/archive outputs
and explicit NIS option selection. They consume libc's existing native rpcgen
yp.h provider with a narrow consumer grant, source yp_prot.h/ypclnt.h providers,
and configured native libc/libsys. No second protocol implementation or SDK NIS
symbol assumption is introduced. ypwhich compiles the original common
yplib_host.c in its own program context and uses its declared source header.
Disabled NIS makes the client programs incompatible and excludes their parent
contributions. Other unfinished optional families are still rejected.

## Evidence under /usr/obj/usr/src

- bazel-nis-clients-native-r1-20261104: normal 16-job build-bsd format-5 passes
  all three archives, both safe alias-list tests and source settings. No network
  query or system domain mutation is performed. ypwhich reads the host domain
  before parsing even -x; no deterministic host-domain-independent CLI test is
  invented for it.
- bazel-nis-clients-make-objects-r1-20261104: fresh original Make object targets
  pass for all four sources under explicit WITH_NIS. These are original object
  targets, not a passing linked/staged client reference.
- bazel-nis-clients-review-r2-20261104: all four exact allocated/symbolic relocation
  object contracts match the independent original Make objects. Three archives
  have nine file payloads, six explicit directories, exact logged payload hashes,
  original yp tags, modes, ownership and flags. Actual native compile/link/archive
  producer records are retained. The first audit assumed every .c input was the
  compile operand; the corrected audit uses the actual unique -c operand and
  retains transitive inputs separately.
- bazel-nis-clients-selection-r1-20261104: configured disabled/enabled parents
  pass with 267/270 archives; the enabled set adds exactly the three clients.
  These queries compile nothing.
- bazel-libc-nis-make-r1-20261104: fresh maintained original libc build and private
  installation reference with WITH_NIS passes. It does not update the SDK or
  establish native/original complete libc binary parity.

The first combined NIS/Hesiod production request failed because libypclnt's
shared link still depended on missing optional SDK libc exports. The correction
binds its existing native libc DSO link interface and libsys, with -nodefaultlibs
and explicit NIS compatibility. Its RPC generators, sources and installed policy
are preserved; no undefined-symbol allowance or SDK substitution is added.
The second request exposed quota's final SDK libc assumption; quota and chpass
now select the configured native libc at NIS-enabled executable links. A third
request rejected libc_nonshared ownership in the libypclnt DSO: it now uses the
same DSO-only libc interface as librpcsvc, while executable wrappers stay at the
program boundary. Bazel export/ownership checks remain enabled. All failed
requests are retained; no wildcard export or undefined-symbol escape is used.

bazel-usrbin-nis-hesiod-native-r4-20261104 passes the entire production parent
with both optional libc features and all four selected tests. Its 271 archives
have no duplicate non-directory destinations. The profile review in
bazel-usrbin-nis-hesiod-profile-review-r2-20261104 verifies the exact four added
archive owners and unchanged 795 of the 801 default archive/request/directory
outputs. chpass and passwd add original NIS aliases; chpass/quota links change.
The remaining changed owner is already-native-libc-linked iconv. Its binary and
debug payloads differ; no byte parity is claimed for them. Exact section review,
readelf and disassembly in the retained r1 profile review establish unchanged
symbol identities and exactly six differing wrapper jumps to the same named
PLT targets after symbol reordering. Both debug CRCs verify. These raw byte and
symbolic differences remain retained, rather than normalized away.

## Remaining gates and dependency finding

Independent complete linked/install/debug parity for the clients, live NIS RPC
and authentication, alternate architectures/configurations, whole world/pkgbase,
bootstrap and controlled performance remain open. Existing library/provider
runtime evidence does not establish live NIS service correctness. No host
installation, upgrade, module loading, publication or reboot is authorized here.
Make remains default and BIP remains excluded.

Actual compiler inputs also expose an incremental-build issue: libsys declares
its implementation include bcopy.c as public textual_hdrs, propagating it through
the native libc link interface into unrelated client compile inputs. This is
not a missing dependency or demonstrated runtime slowdown, but is unnecessary
compile invalidation. Move that declaration behind a private implementation
provider and verify both object parity and downstream action inputs in the next
change. No performance improvement is claimed before measurement.

The existing build-bsd format-5 dispatcher carries the new targets and settings.
No frontend C/schema, staging/signing/publication policy or replacement workflow
is needed; the manual, completion plan and observability ledger are updated.

The final default-profile regression passes separately in
bazel-usrbin-nis-default-regression-r1-20261104. The retained comparison in
bazel-usrbin-nis-default-review-r1-20261104 verifies all 801 default production
archive/request/directory outputs remain byte-identical to the previous passing
default capture. Optional dependency corrections do not alter the default set.

## Public libc ABI boundary follow-up (2026-11-05)

The administration integration exposed the feature-disabled bootstrap libc at
NIS-enabled RPC/wrapper consumer links. The new shared_abi_interface depends on
the actual native libc shared-library producer through cc_import, plus the
original nonshared wrappers. It does not propagate libc implementation linking
inputs into executable links. Strict original yp_mkdb ELF comparison caught and
rejected an earlier candidate with a direct libsys dependency; the corrected
candidate needs only libc, matching Make. No unresolved-symbol allowance, host
DSO substitution or linker-script change was introduced.

Optional RPC/wrapper consumers now select that declared ABI when NIS is enabled.
Legacy shared_link_interface consumers remain to be migrated and checked against
original ELF dependencies; this change does not establish global ABI parity.
See NIS-ADMIN-NATIVE-QUALIFICATION.md for construction and bounded runtime evidence.
