# The authority model

5BSD combines ordinary UNIX with a capability plane. UNIX credentials and file
permissions continue to govern resources that remain in the UNIX plane.
Capability-aware providers can isolate resources and expose controlled
operations through capability endpoints. UID zero does not substitute for the
capability authority required at those boundaries.

The capability policy describes approved software. It does not assign grants
to login accounts. Anyone who can execute an approved client can request the
operations that client exposes, including UNIX root. This is a deliberate
property of the first version, not a per-user consent system.

## Discovery, software identity and capabilities

These are separate pieces:

| Piece | Purpose |
|---|---|
| Process-held discovery route | Locates the broker through ordinary fork and exec |
| Protected software context | Identifies an issuer-approved executable or managed application |
| Kernel-stamped request metadata | Identifies the actual sender without trusting a claimed bundle name |
| Software attributes | Select which endpoints the application may obtain |
| Returned capabilities | Permit operations on specific endpoints, subject to their rights and binding |

Inheriting the discovery route does not inherit management permission. Clearing
the environment or closing ordinary descriptors does not remove the kernel-held
route. A capability-aware library retrieves it when needed; ordinary UNIX
programs need no special channel-preservation code.

SwitchBoard checks endpoint requirements against the actual sender's approved
software attributes. It does not infer them from a UID, environment variable,
pathname string or caller-supplied bundle identifier. Endpoint admission is
separate from operation semantics: a networking provider validates networking
requests, while SwitchBoard need not understand interface names or routing
configuration.

## Executable authority

An exec-only unit declares its program and attributes. SwitchBoard validates the
policy and executable, pins its executable object through a constrained kernel
registration, and registers it for attribution on exec. The entry does not start
a daemon. Managed services receive authority tied to their declared executable
and launch.

A copied executable has a different identity and does not inherit registration.
A hard link still names the same object. Registration prevents in-place writes
to pinned executable contents. Fork preserves the context; an unrelated exec
invalidates its use. Executing another registered program can select that
program's own context. Credential changes do not combine software grants, and
jail transitions invalidate an incompatible context.

Secure execution also matters. Attributed execution uses secure-loader behavior,
and tracing or `no_new_privs` cannot be used to acquire a new privileged software
context. Sandboxed managed programs obtain permitted loader directories from
issuer-owned kernel state, not an untrusted loader environment variable.

These mechanisms do not replace code-integrity policy. Trusted manifests,
verifier enforcement, executable registration, libraries, loaders and mutable
configuration must be reviewed together. A vnode pin or root-owned file alone
is not a signature-verification claim.

## Issuance and revocation

The kernel issuer is a boot-established capability. An ordinary root process
cannot create one merely because its UID is zero. SwitchBoard uses its issuer
to register applications and constrain managed launches. The retired kernel
user-principal authority kind is rejected.

### Roles

A constraint can mark a managed authority with a role. One exists:
`CAP_AUTH_ROLE_DQ_SUPERVISOR` (`0x2` in the constraint's `flags`), the mark a
descriptor-queue supervisor will carry. A role needs exactly one executable
image, is written once together with the constraint, and cannot be added,
removed or changed afterwards. Fork shares the authority; no operation derives
a second one from it, so there is nothing to widen. An authority with a role
cannot be registered as an application. Every other bit of the word is refused
with `EINVAL`, including `0x1`, a value retired before the interface was first
committed and never reassigned. A constraint with no flags behaves exactly as
before.

Be precise about what this is. The kernel checks only what it checks for any
constraint: the caller holds the issuer descriptor, in the issuer's prison.
It does not see a bundle, a signature or an entitlement. The rule that the
supervisor role is granted only to a program from a signed `.cap` bundle that
carries the named entitlement is the issuer's, SwitchBoard's, and is not yet
implemented; SwitchBoard sets no role today. The kernel bit is the carrier of
that decision, not the decision. Nothing in the kernel consults the role yet:
the descriptor queue's checks arrive separately.

There is also temporary, explicitly scoped authority for the boot application
running `/etc/rc`. Its lifetime and endpoint allowlist are separate from login
sessions. It is revoked when the boot phase ends; its discovery route can remain
available without retaining its authority.

Revocation invalidates running contexts and authority-bound handles. It is not
just removal of an entry from future discovery. Unchanged catalogue entries keep
their identity across reload; changed or removed entries revoke the old
registration. Not every arbitrary channel is automatically authority-bound:
providers and brokers must apply the intended binding and transfer rules when
they return capabilities.

Responsible-process attribution and coalitions record process relationships and
accounting. They do not confer software attributes.

## Keeping the exposed authority small

An attributed client must offer deliberate operations and validate its input.
Giving a general-purpose shell or arbitrary-command runner broad attributes
would expose those operations to everyone able to execute it. A provider can
publish narrower endpoints or enforce additional operation-specific restrictions.
User consent can be added as a separate layer where a service needs it.

Resource isolation is what moves a resource out of ordinary UNIX authority.
Merely publishing a capability endpoint does not close an existing UNIX device
or syscall path. The provider must claim and isolate the underlying resource,
including relevant inherited-handle and mapping behavior.

See [Software Attributes](../plane/attributes.md), [Software Policy and Service
Management](../plane/management-policy.md), and [UNIX Authentication and Software
Authority](../providers/auth.md). Fresh-install, upgrade and boot-environment
acceptance remain necessary before treating a source change as a released system.
