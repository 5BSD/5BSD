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

### Attached processes

A process attached to a descriptor queue (`DQ_IOC_ATTACH`) is run by its
supervisor, so it stops acting with a software authority at the attach. The
kernel does there what it does when a process moves to another prison: the
authority stays named, so `CAP_AUTH_INFO` still reports its identity, but it is
marked invalid, the generation advances by one and the invocation binding is
dropped. An authority that was installed and still waiting for its image is
stripped the same way. Sends on endpoints bound to the authority then fail
with `EPERM`. The state is inherited and permanent: an attached process cannot
install an authority and no image it executes activates one. A target with no
authority, or with one already invalid, is left as it is.

One thing outlasts the strip. Until the attached process executes an image
its memory is a copy of its creator's, which may hold the authority, so the
stripped authority keeps deciding who may debug it: a debugger that is not
itself stripped gets the answer it got before the attach. After the exec it no
longer restricts debugging. The strip takes the authority and nothing else:
the discovery context, the process identity and endpoints not bound to an
authority are unchanged.

The stripped process is a different matter as a debugger. Its authority is
invalid, so it fails the authority's debug check for every process the
authority still protects: the holder, another target stripped of the same
authority, and a child it forks, whose `PT_TRACE_ME` fails too. The error is
`EPERM`; before the attach all of these were allowed. All four refusals are
the rule, a documented difference from ordinary Unix behaviour: the strip must
not leave a confined process a way to the holder's memory, and a child or a
target stripped later may hold a copy of it.

What ends a refusal is the protected process ceasing to be protected, not
anything the stripped process does. A stripped child or other stripped target
stops being protected when it executes an image, and can then be debugged
subject to the ordinary checks. The holder stays protected for as long as it
holds the authority, across its own image executions, so the stripped process
is refused towards it for good. The stripped process's own exec ends only the
protection of the stripped process itself; its authority stays invalid and it
passes the check for no process it was refused before.

Debugging and inspection are separate questions. The authority's debug
protection (and the no-ambient protection of a `PD_PROTECTED` child) refuses
debugging: stopping the process, reading or writing its memory, its
environment and descriptors. It does not refuse inspection, the process's
memory map, auxv, ps_strings and signal trampoline locations, umask and
kernel stacks (`p_caninspect(9)`), which `procstat -v -k -x` and DTrace's
symbolisation and USDT registration need. Inspection never reads the
process's memory contents.

These rules were not decided by the project owner. The form of the strip
(D362), the debug protection lasting until exec (D363), and the refusal of
the stripped process as a debugger in all four cases, were decided by the
coordinating session under the owner's delegation and can be revised by the
owner. The decision table in the project's descriptor-queue chapter carries
the rows. An allowance for a stripped process to debug a child it forked
after the strip was considered. It is a recorded option only: not built, not
scheduled, and the kernel has no part of it.

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
