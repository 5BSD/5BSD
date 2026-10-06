# Per-user agents

Per-user agents are managed units owned by a UNIX account. Supervision and
ownership do not make their user-writable manifests trusted grant sources.
For the overall model, see [Software Attributes](../plane/attributes.md) and
[The Management Model](../plane/management-model.md).

## Installation and discovery

SwitchBoard scans existing `/Capabilities/Users/<uid>/Agents` roots at startup
and reload. The directory and bundle trees must have the expected owner and
pass registry trust checks. A login or status request does not create these
directories automatically; provisioning them is a separate system-builder
choice. A user-owned tree cannot register an `activation { exec = true; }`
application as trusted software.

## Launch restrictions

The launch policy forces user-owned agents to `control = "user"` and
`domain = "user"`, removes user visibility from their published endpoints,
disables ambient launch, strips system gates and software attributes, and
clamps privileged priority requests. Agents use the normal capability-mode
launch path. Declaring a protected endpoint attribute in a user-writable
manifest cannot grant it.

User-owned agents run as the account identified by registry ownership, with
that account's primary and supplementary groups. Their manifest cannot select
root or another account. The native child drops credentials before opening
bundle configuration, resource directories and executable paths. Manager-created
activation sockets are reserved for trusted bundles. The supervised identity
is pinned to the owner's executable with no software attributes; loader inputs
come from the trusted system library directories, not a user-writable private
library directory.

## Management and access

The USER management class permits the owning UID or an authorized management
client after control-endpoint admission. Ownership alone does not supply
endpoint attributes. The shipped approved `switchboardctl` has software
management authority; any user permitted to run it can use its exposed
management operations subject to CORE restrictions. V1 therefore does not
promise that only an agent's owner can operate the shipped administrative
client.

A user agent can use endpoints available to its discovery domain that require
no attributes. Protected services require trusted software with approved
attributes. If an agent needs such access, install and review an appropriate
trusted application or narrowly scoped provider instead of granting authority
from the user's writable bundle tree.

Agents are not login sessions. Boot and other activation sources determine
when they run; logging out does not inherently stop them. Directory watches
and reload behavior are described in [SwitchBoard](../plane/switchboard.md).
