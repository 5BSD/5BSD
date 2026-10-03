# Principal grants and service management

5BSD uses anointments to authorize endpoint connections. The system builder
configures user grants in `/Capabilities/Config/principal-policy.ucl`; managed
units receive their declared bundle grants. Anointments are permission names,
not user roles and not service-specific operation descriptions.

SwitchBoard checks endpoint `requires` against the holder's grants. Providers
need no attribute-policy engine when every holder of an endpoint receives the
same access. Providers remain responsible for request validation and any finer
restrictions their own protocols expose.

## User policy

An example with independent endpoint and management permissions:

```ucl
principals {
    alice {
        uids = [1001];
        anointments = ["network.admin"];
        may_elevate = ["storage.admin"];
        admin_rights = false;
    }
    operator {
        uids = [0];
        anointments = ["system.switchboard.admin"];
        admin_rights = false;
    }
    default { anointments = []; admin_rights = false; }
}
```

The networking/storage names above are illustrative: use the actual `requires`
names published by installed providers. Entries match in file order; the first
matching UID or group entry wins. The fallback grants nothing in this example.
The shipped root/wheel `*` profile remains an explicit compatibility choice,
not an implicit UID-0 privilege. Missing or invalid policy grants nothing.

`system.switchboard.admin` permits SYSTEM lifecycle management and global
SwitchBoard control operations. Owners retain control of their USER agents.
CORE lifecycle control remains unavailable to every runtime operator. The
current management grant is coarse: it does not select individual SYSTEM
units. There is no separate attribute-based management-policy file or boot knob.

`admin_rights` is a separate provider-side ADMIN flag, not the management grant.
It defaults to true for `*`; set it explicitly to false when endpoint reach
must not imply provider bypass. Broad grants should always be reviewed together
with this field.

`system.auth.mint` permits asking BSDAuth to establish a session for a named UID
without having BSDAuth authenticate that user's password. This is powerful
impersonation authority intended for trusted authenticators. It is distinct
from ADMIN. The boot carry and deliberately configured `*` holders receive it;
a mere service-management grant or provider ADMIN bit does not. Ordinary
managed units never receive this bit through endpoint lookup.

## Loading and tools

BSDAuth loads and validates the policy once at startup, precomputing grants.
Session decisions do not reopen or reparse the policy. Replacing the file or
changing its contents does not alter that running instance's policy snapshot.
The snapshot is bounded to 128 principal entries and the existing file/name
limits. Invalid input produces no protected grants, including for root/wheel.

`policyctl init` prints an empty policy for editing. `policyctl validate FILE`
checks a candidate with the same parser; `policyctl format FILE` prints JSON
without changing rule order. `policyctl explain FILE USER` previews the grants
using the local account databases. For offline BEs, run the tool inside the
candidate environment. A preview does not change or inspect existing sessions.

Normal UNIX programs inherit their session authority. Changing UID does not
mint new capability grants or erase held descriptors. Trusted login, SSH, and
user-switching paths must install the intended session and close stale ones.
Full-discovery sessions retain their actual authenticated UID.

## Installer choices

The interactive installer runs policy setup after account creation and lists
accounts by name and numeric UID. It offers full capability access (`*` and
provider ADMIN) separately from SYSTEM management (`system.switchboard.admin`
without provider ADMIN). Root/wheel full access is an explicit compatibility
choice. Selecting explicit grants allows root to receive no capability grants,
or to receive only management authority, like any other account.

Scripted installations retain compatibility unless configured otherwise. For
example, after creating Alice and Bob in the post-install hook:

```sh
BSDINSTALL_CAPABILITY_COMPAT=no
BSDINSTALL_CAPABILITY_ADMIN_USERS=alice
BSDINSTALL_CAPABILITY_MANAGE_USERS=bob
export BSDINSTALL_CAPABILITY_COMPAT BSDINSTALL_CAPABILITY_ADMIN_USERS
export BSDINSTALL_CAPABILITY_MANAGE_USERS
```

Alice gets full access; Bob gets SYSTEM management only; root gets neither.
Full access wins if an account matches both selections. For individual endpoint
names or elevation grants, edit the generated principal policy and validate it
with `policyctl`. Choosing no accounts with compatibility disabled produces an
empty policy. None of these installer choices enrolls an owner signing key or
establishes a trusted boot chain.

## Boot environments and activation

The intended persistent update boundary is an authorized, inactive boot
environment containing policy, trusted manifests, and matching system code:

1. Clone the current BE and mount the candidate.
2. Update the candidate's grants and matching account configuration.
3. Validate the policy and review effective grants, including recovery access.
4. Publish through the owner's authorized integrity/update mechanism.
5. Activate for one boot, test login and endpoint permissions, then make permanent.

On the standard layout, `/Capabilities/Config`, `/Capabilities/System`, `/etc`,
and `/var/db/pkg` belong to the root BE. Do not move policy into a shared dataset
or make `/var` shared for this workflow. Shared application data is not rolled
back with policy and must remain compatible with any permitted rollback.

A reboot destroys the previous processes and channels. Merely editing a file,
logging out, or removing an anointment does not promise revocation of every
already-issued descriptor. There is no general live policy-update API.

## Security qualification still required

A policy snapshot is not a filesystem seal. An authorized boot/update boundary
must protect the policy, account identity inputs, manifests, executables, and
boot selection. Without those protections a daemon restart can load modified
files, and runtime root may still undermine the intended restriction. Veriexec
must actually be configured and enforcing; O_VERIFY alone is not a seal.

Existing mac_capability process shields, resource claims, and system gates
provide substantial enforcement. Their coverage and lifetime must be tested
against root, including workers, service failure/restart, inherited descriptors,
mounts, raw-device access, identity changes, and boot rollback.

The current selectors bind to numeric UIDs and group names, not immutable
account generations. Before deleting or reusing a UID or privileged group,
remove its grants in the candidate policy and review the candidate account
databases together. Reusing an old UID while retaining its rule transfers that
rule to the new account. Group changes can affect new sessions even while the
policy document itself is snapshotted; existing sessions keep their grants.
Account identity protection is therefore part of the security boundary.

The boot carry currently holds `*`. Trusted authenticators and any processes
that inherit that authority are part of the trusted computing base. A protected
profile must narrow its distribution and protect authenticators against process
injection and executable/configuration replacement; shielding BSDAuth alone does
not protect every process able to ask it to mint a session. Ordinary UNIX powers remain ordinary
UNIX powers unless they cross a protected boundary.

BE activation by itself is not authorization. The final protected profile needs
an owner-controlled publishing/recovery path; booting an older, more permissive
policy must be deliberate owner recovery, not a runtime root bypass. Automatic
health checks and watchdog rollback are separate from bectl's one-boot selection.
The current snapshot/tool changes do not claim those remaining protections are
implemented or qualified.
