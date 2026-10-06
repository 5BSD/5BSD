# The Management Model

5BSD assigns capability authority to approved software. A UNIX account does
not acquire software attributes by logging in, changing UID or becoming root.
The inherited discovery channel is a route to services, not an administrative
credential. SwitchBoard checks kernel-stamped sender identity and the current
software policy when admitting requests.

An ordinary UNIX user who can execute an approved control client can use the
operations that client exposes. V1 has no additional user-consent layer. UNIX
permissions still decide who can execute the file and perform ordinary UNIX
operations. See [Software Attributes](attributes.md) and
[Software policy and service management](management-policy.md).

## Discovery, management and process protection

| Manifest key | Responsibility |
|---|---|
| `control` | Management class: `core`, `system` or `user` |
| `visible` | Discovery domains in which a provider's names are visible |
| `domain` | Discovery scope used by a managed unit |
| endpoint `requires` | Software attributes needed to obtain that endpoint |
| `protect` | Protection against operations on the process, such as signals or tracing |

These restrictions compose. Seeing a name does not grant its endpoint, and
obtaining an endpoint does not remove the provider's operation checks.
SwitchBoard handles discovery and service management; resource-specific
checks, such as which network interface a request may change, belong to the
provider.

## Management classes

`usr.sbin/switchboard/management.c` enforces the class in addition to control
endpoint admission and operation authority:

| Class | Runtime management |
|---|---|
| `core` | Denied to all runtime management clients, including root and attributed administrators |
| `system` | Requires software management authority |
| `user` | Retains the owning-UID or management-authority check; this does not itself grant control endpoint access |

SwitchBoard's own boot, shutdown and recovery lifecycle manages CORE units.
CORE examples include the filesystem, audit, logging, time, power, system
extension and sysctl providers. A normal administrative client cannot stop
or restart them through runtime control requests.

## Approved control software

The shipped `switchboardctl` executable is installed inside its trusted
control bundle. Its manifest declares:

```ucl
program = "switchboardctl";
activation { exec = true; }
attributes = ["system.switchboard.admin"];
```

The ordinary `/usr/sbin/switchboardctl` command points to this registered
executable. Its authority comes from that software registration. A copied,
unregistered executable does not gain authority by sharing its filename or
by running as root. Managed services can also obtain control access when
their validated software attributes permit it; daemon status is not itself
an administrative credential.

Mutating control operations check both current sender authority and the
rights on the returned capability. Inheriting an old channel does not make an
unapproved shell an administrator. Reload and revocation must also invalidate
stale software contexts and context-bound capabilities; see
[Software policy and service management](management-policy.md).

For example:

```sh
switchboardctl status
switchboardctl services
switchboardctl restart system.Network/bsdnetwork
switchboardctl reload
```

These commands need the approved software's attributes. They do not require a
login-principal policy or a per-command authentication wrapper. Stopping a
CORE unit remains denied even through the approved client.

## UNIX and integrity boundaries

The software model does not promise that ordinary root has lost every UNIX
power. Process protection, resource isolation, trusted installation paths and
executable integrity are separate enforcement mechanisms. Removing a device
from ordinary UNIX access requires the corresponding isolation mechanism and
an attributed provider; endpoint policy alone cannot protect a device that
remains directly accessible.

Installing a bundle may require UNIX permission to write its destination.
That file permission is separate from permission to request capability-plane
operations. Untrusted per-user bundles do not become trusted system software
because their owner wrote attributes in a manifest. SwitchBoard also does not
create a per-user agent directory merely because a client requests status.

Responsible-process attribution and coalitions provide accounting and process
association. They do not grant software attributes.

Prepare policy and executable changes together in a boot environment, validate
the new system, and retain a rollback environment. Verifier enforcement,
libraries, loaders and writable configuration remain part of the integrity
boundary. Do not infer a sealed system from capability admission alone.

Reference: switchboard(5), switchboard(8), switchboardctl(8),
[Descriptor and Process Protections](../capability/descriptor-protections.md).
