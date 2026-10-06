# UNIX authentication and software authority

UNIX authentication establishes UNIX credentials. Login, SSH and `su` use their
normal authentication paths; they do not obtain capability permissions for the
account or replace the discovery channel when the UID changes.

Capability-plane admission follows the executable's approved software policy.
The kernel holds the discovery route on the process and supplies trustworthy
software-authority metadata with requests. SwitchBoard compares that authority's
attributes with the endpoint's requirements. See [Software
Attributes](../plane/attributes.md) for manifest examples and the code-integrity
boundary.

A shell receives no administrative capability authority just because its UID is
zero. When any UNIX user executes an approved control program, that program can
obtain the capabilities allowed by its attributes. Its children inherit its
context on fork; executing unrelated software invalidates that context. Another
approved executable can acquire its own registered context on exec. Changing
UNIX credentials does not combine or enlarge software grants.

The discovery route is inherited separately. Keeping it across fork, exec,
`closefrom`, or environment cleanup does not convey the parent's attributes.
There is no need to patch each UNIX program to preserve an environment variable
or a special inherited descriptor.

## Removed login-grant machinery

BSDAuth, the `anoint` command, principal-policy parsing, and client APIs for
session minting and elevation have been removed from the source build. The
`mint_authority` and `authenticator_exec` manifest declarations are rejected.
The kernel rejects the retired user-authority kind, and SwitchBoard rejects the
retired session-mint and user-authority protocol operations.

The `pam_capability` module remains an inert compatibility module for locally
preserved PAM configurations. New PAM stacks do not use it. It neither
authenticates nor grants authority. Removing it from a local stack must preserve
that stack's ordinary authentication modules.

Removing source components does not uninstall an old package or migrate an old
configuration automatically. Upgrade and fresh-install acceptance must verify
that obsolete Auth bundles and principal policies are not active.

## What this model does not promise

Software attributes do not distinguish Alice from root when both execute the
same approved program. The program must validate requests and expose only its
intended operations. Granting an interpreter or arbitrary-command runner broad
attributes would expose that authority to its callers.

User consent or additional operation-specific authorization can be implemented
by a service when needed. They are separate from discovery inheritance and are
not login-principal grants in this version. Resources still in the UNIX plane
retain UNIX permissions; resources isolated by capability-aware services use
their capability interfaces.

## Upgrade cleanup

Source-based upgrades list the retired Auth bundle, `anoint`, authentication
protocol header, installer policy step, and obsolete tests in `ObsoleteFiles.inc`.
Run the normal obsolete-file review and removal against the upgraded boot
environment. Merely installing a new world does not remove old files.

For pkgbase upgrades, the retired `bsdauth` and `bsdauth-tests` packages also
need removal; absence from a new repository does not prove that installed
packages have been deleted. Verify that `/Capabilities/System/Auth.cap` is no
longer an active bundle before accepting the upgraded system. The old
`principal-policy.ucl` is not read by this model; preserve any local copy for
review, then archive or remove it explicitly. The inert `pam_capability`
compatibility module permits old local PAM stacks to load during migration;
new stacks do not need it.
