# Native rescue installation and pkgbase qualification (2026-11-05)

## Implementation

The actual //rescue/rescue:rescue executable uses an original crunchgen dispatcher
with EXECNAME=rescue. It is not a renamed rescue_core. Per-program C stubs are
independent of the dispatcher name and remain shared, along with the crunched
objects and internal helper replacements. assembly.bzl centralizes configured
dispatcher declarations and the exact static link policy in ordinary Starlark
macros. Dispatcher compile options remain shared with the bounded core.

installation.bzl follows original bsd.crunchgen.mk/Makefile policy: no separate
debug installation (MK_DEBUG_FILES=no), one stripped /rescue/rescue, original
program/alias hardlinks, /rescue/dhclient-script, and an explicitly owned /rescue
directory. The three login argv aliases -sh/-csh/-tcsh remain dispatcher names,
but are not installed links. Ping6 installation requires both a selected ping
and INET6_SUPPORT. Source-owned configured selections govern actual link entries.

The DHCP producer executes the original one-line sed expression on the maintained
sbin/dhclient script, changing only its first-line /bin/ interpreter prefix.
bsd_sed_output shares the former version-filter action implementation; the old
version-filter interface, input/tool/runtime/environment contract and action
mnemonic remain unchanged. There is no handwritten substitute DHCP body or
shell wrapper. Inputs, selected sed and output redirection are declared actions.

The rescue parent now contributes installation and both internal library variants
to the maintained world aggregates under the new rescue boolean setting (default
true, corresponding to Make's MK_RESCUE). Both enabled and disabled actual world
graphs were queried successfully. This is graph membership, not a fresh complete
world build. Existing format-5 settings/targets and build-bsd bazel-test suffice;
no C frontend, signing or publication policy change is needed. Manual and plan
are updated in the same change. Make remains the production/default backend.

packages/rescue/BUILD.bazel uses the existing rescue.ucl and existing Make package
policy: one rescue package, no dbg/dev/man subpackages, minimal set and maintained
default package identity fields. Its ABI comes from the actual stripped ELF.
The package is built by the existing native layout/UCL/pkg drivers, with explicit
version and compression thread settings. It is an unsigned qualification output,
not a published repository, boot-verification result or BIP protection.

## Verified evidence

All evidence is under /usr/obj/usr/src.

- bazel-rescue-installation-native-r6-20261105: maintained frontend, 16 jobs;
  107 broad runtime, five configured runtime, six installed-layout runtime and
  28 source-setting methods pass. The actual package and rescue parent internal
  products build. NIS=false matches the recorded original world selection.
- bazel-rescue-installation-make-r1-20261105: maintained install-reference.py
  builds the complete original rescue parent, including its applications and
  internal replacements, and installs to a private stage with logical NO_ROOT
  metadata. Its regular application catalog has 592 objects. It uses the
  selected Make-built SDK/common libraries; it is not a newly built full world
  or a complete hermetic dependency proof.
- bazel-rescue-installation-review-r3-20261105: all 142 actual component records
  match original Make paths, owner/group, mode, package tags, flags and inode/link
  relationships: one directory, two regular payloads and 139 hardlinks. Every
  package-owned tar member agrees, with the common archive container root checked
  separately. Original and native DHCP script bytes match. Original staged
  dispatcher list, echo and shell behavior pass independently.
- Six maintained installed-layout methods extract only into private test storage
  and exercise actual rescue-named dispatch, hardlinks/modes, suppressed login
  aliases, argv[0] replacement with AT_EXECPATH fallback, binary stdin/bracket
  alias, script/no-debug policy and static AMD64 ELF/NX/RELRO properties. This
  does not run PID1, chroot to a damaged system, or execute /rescue helpers at
  their true guest-root absolute paths.
- bazel-rescue-installed-pipeline-review-r2-20261105: original Make on identical
  captured native application/common/helper/startup inputs reproduces all 208
  whole outputs for the rescue-named executable. This does not mean independently
  rebuilt complete-library/debug ELF byte identity.
- bazel-rescue-world-membership-r1-20261105: actual cquery world dependency graphs
  include the rescue installation parent with rescue=true and exclude it with
  rescue=false. No world compilation/install is claimed by this query.
- bazel-sed-producer-preservation-r1-20261105: existing version-filter action
  semantics and attribute contracts preserved exactly; actual DHCP generation
  independently matches original Make output. Not every version-map consumer
  was rebuilt by this observer.
- bazel-rescue-package-review-r2-20261105: one real 5BSD-rescue package has the
  expected name/version/set, no scripts/dependencies, all 141 nondirectory paths
  and its one directory. pkg-static reads it. Script and ELF payload bytes bind
  to the verified native installation. Private BSD tar extraction preserves all
  modes and hardlinks, including pkg's legitimate choice of '[' as the physical
  hardlink anchor. No package contents were renamed to force identity.

## Independent ELF differences remain open

The initial native development candidate uses debug malloc; the recorded Make
SDK profile enables production malloc. The explicit matching production-malloc
control in bazel-rescue-installation-production-malloc-native-r1-20261105 also
passes all 146 methods and builds its package. This does not authorize publication
or change the default development malloc policy.

bazel-rescue-malloc-control-r1-20261105 records untouched sizes/hashes/allocated
sections: native debug 19,882,344 bytes; native production 19,778,424; independent
Make 19,781,488. Matching the option reduces the size discrepancy from 100,856 to
3,064 bytes; raw complete ELF bytes still differ. Remaining differences are not
silently attributed to paths or ignored because smoke tests passed.

bazel-rescue-all-objects-review-r1-20261105 compares all 592 application objects
against the fresh full Make reference. Exactly 503 allocated/symbol/nondebug
relocation contracts match directly. Of 89 differences, 45 have .rodata.str1.1
payload differences, 23 provider objects have .SUNW_dof differences, and 21 have
symbol/relocation differences with matching allocated bytes. No application
allocated-code difference was found by that contract, but the remaining strings,
DOF and bindings still need controls. Common-library/startup/selection differences
and raw debug parity also require reconciliation; the final executable's text
size differs by 6,176 bytes in the matching-malloc comparison. Do not call complete
independent rescue ELF parity, runtime tracing or system qualification finished.

## Retained failures and remaining work

Native r1 rejected shared **kwargs in BUILD files; declarations moved into normal
source-owned .bzl macros. R2's installation test used Python's data extraction
filter, which adds owner-write permission. The standard tar filter now preserves
archive modes and all exact mode assertions remain. After r3, inspection of independent Make metadata revealed the missing
explicit owned /rescue directory; r4 corrected it. First
observers also retained their exact root-container and unrequested dispatcher
capture failures; final source/archive comparisons use immutable captures.

The first package observer assumed relative member names and failed on pkg's
absolute paths. The corrected observer validates the actual manifest/inventory,
then uses standard tar's private extraction. None of these failed runs is deleted
or reported as successful.

Host uid is 1001 with no sudo/doas command available. The maintained private-root
pkg add/check/delete helper explicitly requires OS root for its database and
ownership qualification. The concrete command is prepared in:

    /usr/obj/usr/src/bazel-rescue-package-review-r2-20261105/root-command.txt

It uses the hash-checked private package inputs and a fresh /usr/obj root, not the
host root; it has not run. A guest root can supply this qualification without
installing anything on the host. Private tar extraction is not a substitute for
pkg database/add/check/delete qualification.

Next reconcile the recorded independent application/provider/library differences,
qualify package database operations, and run real guest recovery/helper/PID1 and
normal system/service cases. Complete remaining option and architecture matrices,
refresh full world/kernel/modules/pkgbase, bootstrap/reproducibility/cache/sandbox
and CPU/memory/disk qualification. Hardware stays separately built and combined
publication remains gated under /usr/obj/usr/src/repo. BIP stays excluded. No host
installation, upgrade, reboot or publication occurred.
