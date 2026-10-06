# Discovery and application authority

The current design direction is software-centric. UNIX users retain ordinary
UNIX permissions. Capability attributes describe the controlled service access
of attributed applications; logging in or changing UID grants no capability
permissions. Earlier user-principal grant tests are historical evidence for the
previous design, not acceptance evidence for this replacement.

Every process inherits a kernel-held discovery route. That route locates
SwitchBoard and does not confer application identity or administrative access.
The kernel stamps requests with trustworthy sender identity; callers cannot
claim an application by supplying its bundle name or a UNIX UID.

An attributed resource owner can isolate a resource such as `/dev/pf` from
ordinary UNIX access. Approved client applications access the resource through
the owner's published interface. Anyone allowed to execute such a client can
request its exposed operations: the application and provider must deliberately
choose those operations and validate their inputs. No global login-grant policy
is required for this model.

## Software attributes

A client manifest declares `attributes = ["system.trace.client"]`. A server
endpoint declares `requires = ["system.trace.client"]`. SwitchBoard admits the
client only when its kernel-attributed software identity has every required
attribute. A supplied string, UID, or inherited discovery route is not proof.

`attributes` is the canonical manifest key. Existing `holds` declarations remain
an upgrade alias with the same validation; specifying both keys is an error,
including an empty list, to avoid ambiguous grants. Wildcards remain prohibited.
Internal identifiers and older documentation are still being renamed; the
legacy user-elevation command is being retired rather than renamed as a new
way to grant attributes to users.

## Implemented transition

Shipped PAM stacks no longer request capability grants. An inert
`pam_capability` module remains solely for locally retained upgrade
configurations; it authenticates nobody, issues no authority, and changes no
process state. SwitchBoard rejects the retired login-principal issuance RPC and
no longer reads principal policy. BSDInstall no longer assigns capability grants
to accounts. BSDAuth no longer installs a principal-policy configuration file.

Managed application grants are constrained to their launch executable by
default. Existing explicitly configured executable constraints remain under
cleanup. The kernel pins executable vnode identities: a different executable
cannot retain a constrained application's grant merely by inheriting its
process state. Fork preserves permitted application context; ordinary UNIX
credentials and discovery are separate. Responsible-process attribution and
coalitions remain accounting mechanisms, not authorization.

The short-lived boot-script grant remains separate and scoped to its required
endpoint. Boot-script authority, legacy user-token interfaces, and the old
application/authenticator distinction still require cleanup.

## Resource isolation

Isolation rechecks the active writer on vnode writes, including inherited open
files. It refuses claims over potentially writable shared mappings and refuses
new such mappings while a claim exists. Private copy-on-write and genuinely
read-only shared mappings remain available. The mmap MAC hook receives maximum
as well as current protection; MAC module ABI version 10 requires matching
rebuilt modules.

These checks are prerequisites for reliable resource ownership, not a complete
persistent configuration-protection mechanism. Namespace replacement, aliasing,
claim lifetime, and provider recovery remain under review. The earlier proposal
to protect authentication databases specifically to preserve user capability
grants has been superseded; trusted application code and security-critical
configuration still require integrity protection.

## Remaining acceptance work

The kernel now supports issuer-controlled ordinary-exec attribution, including
secure-loader behavior and pinned executable contents. SwitchBoard now loads and reloads exec-only bundle policies and registers their
executable identities. This does not modify login, su, SSH, or each UNIX launcher.
Integrated service and ordinary-login acceptance is still in progress. Executing an unrelated program
must discard old application authority; requesting services must never trust an
inherited discovery route as proof of application identity. Interpreter, loader,
library injection, debugging, and cached-handle boundaries require explicit
tests. Signature/veriexec enforcement must be distinguished from mere pathname
or ownership checks; opening with O_VERIFY alone is insufficient when verifier
enforcement is disabled.

Remove obsolete user-grant APIs, principal-policy tools, authentication-provider
handoffs, and their tests after replacing useful coverage with application
identity and resource-ownership tests. Then verify stock login/su/SSH, approved
and unapproved clients, UID changes, exec/fork/delegation, DTrace, provider
recovery, BSDInstall, and boot environments. Final release acceptance requires an
empty-object world/kernel/modules build and fresh installer VM, followed by the
requested amd64 and Raspberry Pi artifacts and authorized dev/release publishing.

## Required deep-cleanup gate before release

The final source audit must account for the entire abandoned user-grant model,
not merely hide its configuration. Remove unused BSDAuth login mint/elevation,
principal policy parsers and account resolvers, the anoint command, obsolete
wire operations and client APIs, authenticator-specific exec lists, and their
installer/package entries. Replace useful security tests with software-identity
coverage; remove tests whose success asserts the old model. Update manuals,
book chapters, examples, build helpers, and VM fixtures together.

Inspect login, su, SSH, getty, cron, atrun, and display-manager handoffs for
remaining environment/descriptor preservation code. Ordinary UNIX programs
must not acquire custom capability identity logic. Preserve unrelated fixes.
Any compatibility symbol or module that remains must have a documented upgrade
purpose and must not mint, elevate, or manufacture authority.

Keep responsible-process and coalition attribution independent of authorization.
The retired grant-owned login-coalition registry has been removed from
SwitchBoard; a software grant or matching UID is not evidence of a session
coalition. Kernel coalition support and real managed-service parentage remain.

Acceptance requires an inventory with each item removed, replaced, or explicitly
justified; builds and focused regressions; then the fresh world/installer/VM
checks. Search results and component tests alone do not close this gate.

## Secure loading of managed services

Software-attributed exec uses secure-loader behavior without changing a UNIX UID.
The loader ignores unsafe `LD_*` input. For a service born in Capsicum, the issuer
attaches up to three library-directory file references to its constrained grant:
the system directories and an optional private unit directory. The kernel retains
their descriptor rights and exposes fresh close-on-exec descriptors only to a
valid, executed authority context. A pending grant cannot retrieve them.

The runtime linker obtains this list from the kernel rather than trusting
inherited environment values or descriptor numbers. Ordinary unprivileged exec
does not query for this list. SwitchBoard no longer opens and advertises an
`LD_LIBRARY_PATH_FDS` list during child setup. Read access to a directory does not
prove its contents are signed; library integrity remains part of the separate
verifier and resource-protection acceptance work.

The isolated kernel VM passed 1,005 checks with this handoff, including pending
exec denial, issuer checks, descriptor-rights preservation, and a sandboxed
dynamic executable with hostile loader environment settings. This is component
evidence, not the final fresh-world, installer, or release acceptance.

BSDAuth and the `anoint` program have been removed from the source/build. Their
old library APIs, wire definitions, principal parser, and historical documentation
still require cleanup. Upgrade removal of previously installed packages must be
verified separately; deleting a build target alone does not uninstall it.
