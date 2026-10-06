# Sessions: login, su, ssh and cron

A process holds its discovery route in kernel process state, independently of
its descriptors and environment. Fork and exec preserve the route. Closing
descriptors or replacing the environment does not lose it. A capability-aware
library obtains a private working channel when needed; ordinary UNIX programs
need no special FD-preservation code.

## UNIX authentication stays UNIX

Login, SSH, `su`, cron, and `at` retain their normal account and authentication
behavior. They do not ask BSDAuth for user grants, install capability authority
through PAM, or replace discovery channels when changing users. BSDAuth and the
`anoint` elevation command are retired. New PAM stacks do not use
`pam_capability`; its remaining module is an inert migration compatibility stub.

| Event | Discovery | Software authority |
|---|---|---|
| Fork | Inherited | Permitted context inherited |
| Exec | Retained | Re-evaluated for the executable |
| Change UNIX UID | Retained | No account-based attribute change |
| Close descriptors or clear environment | Retained | No attribute change |
| Incompatible prison transition | Not a way to escape confinement | Existing authority becomes unusable |
| Process exit | Held reference released | Process references released; issuer/revocation rules still apply |

A kernel-held route makes transport transparent to display managers and other
login providers. It does not make a shell privileged. An ordinary shell can
execute a registered client, whose approved executable receives its own
attributes. An unrelated image cannot retain that client's attributes on exec.
See [Software attributes](../plane/attributes.md).

## Who may run an approved client

UNIX permissions decide whether an account may execute a program. Any account
that can execute an approved client may use the operations it exposes, including
UNIX root. The capability plane checks which software is requesting access,
not whether the invoking account belongs to wheel or authenticated recently.

For example, an approved network client may obtain an endpoint requiring its
network attribute. An unregistered copy cannot manufacture that authority by
claiming the same bundle name or changing UID. The server exposes the permitted
operations and validates requests. If the server isolates `/dev/pf`, callers
must use that interface rather than bypass it with ordinary UNIX device access.

Approving a general-purpose shell or interpreter with broad attributes would
expose those privileges through whatever code it can run. System builders
should approve clients whose operations they intend to make available. A
per-operation consent or account-authorization layer is a separate future policy
choice, not an implicit property of login.

## What a shell holds

A shell may have only descriptors 0, 1, and 2 and still have discovery. An empty
`SERVICE_LOOKUP_FD` is expected. `service_process_info()` reports process context;
`service_ambient_lookup_fd()` returns an owned working lookup channel, which the
caller closes after use. Independent working handles have private reply queues.

A route is not an administrative credential. SwitchBoard uses kernel-stamped
sender authority for endpoint admission. Control mutations additionally require
the software's management attribute and the held management right. Changing to
UID 0 alone supplies neither.

A program without a discovery route can still use ordinary UNIX interfaces.
A capability-aware client must report when it cannot reach a required service.
Kernel-held references do not recreate server-side state after SwitchBoard dies;
route recovery needs separate handling and must not grant stale authority.

## Verification and remaining boundaries

Development QEMU tests exercise stock console login, `su`, and SSH password,
keyboard-interactive, and public-key authentication with and without PAM. They
also exercise empty environments, descriptor closing, approved-image access,
and unregistered-copy denial. Fresh installer and release-artifact acceptance
are separate gates.

Executable registration and isolated resources do not by themselves establish
complete code integrity. Approved binaries, trusted loaders and libraries,
configuration, and policy updates all need protection. Coalitions and
responsible-process attribution describe process relationships and do not grant
attributes. Upgrade removal of retired components is described in
[UNIX authentication and software authority](../providers/auth.md).
