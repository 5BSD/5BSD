# Software policy and service management

This chapter describes the current software-authority implementation. The
[system security design](../capability/system-security.md) extends the intended
model with independent user authorization, mandatory system integrity, verified
boot and authenticated recovery. Those additional protections remain under
implementation and must not be inferred from software attributes alone.

The system image assigns attributes to approved software. There is no
`principal-policy.ucl` mapping login accounts to capability grants. UNIX account
management and authentication retain their UNIX meaning.

For example, the shipped SwitchBoard control client declares:

```ucl
program = "switchboardctl";
activation { exec = true; }
attributes = ["system.switchboard.admin"];
```

This is an executable policy entry, not a daemon to start. SwitchBoard registers
the approved executable with the kernel. Executing it establishes its software
context, and the kernel stamps requests with that context. Copying the executable
to an unregistered inode does not copy its registration. A hard link names the
same executable object; moving or linking that object does not create a separate
software identity.

The attribute admits the approved client to management operations. Running an
unapproved shell as root does not confer this attribute. On a development kernel, an ordinary UNIX user who can execute the approved
client can use its exposed operations. In the mandatory integrity profile,
management additionally requires an independent live session right. The shipped
session policy enrolls no authenticator; protected human login remains unfinished.

Control and lifecycle channels are additionally bound to the requesting process
identity and execution nonce from kernel receive metadata. A forked child or a
new execution cannot reuse a held control channel. A child may request a fresh
channel according to its own software eligibility. The broker separately associates authenticator-issued routes with bounded
principal rights. Neither invocation binding nor the broker's session-issuance
API proves that a human was authenticated; protected authenticator integration
remains an implementation gate.

## Management classes still apply

Endpoint admission does not remove a service's management class:

- `core` services cannot be stopped or restarted by runtime management clients.
  SwitchBoard's own boot, shutdown and recovery lifecycle manages them.
- `system` services require management authority.
- `user` services retain the existing owning-UID or management-authority class
  check. That check does not itself grant access to the control endpoint.

Providers retain responsibility for validating requests and any finer operation
restrictions. SwitchBoard does not need rules describing network interfaces or
other service-specific resources.

## Reload and revocation

Application catalogue reload preserves unchanged registrations. A change to the
executable identity, software scope or attributes replaces its registration;
removing the policy removes its registration. The old authority is revoked
before replacement. Revocation invalidates its running contexts and
context-bound capabilities, not merely future discovery requests.

Catalogue validation failure preserves the previous catalogue. A failure while
applying replacements is reported and can leave a partially updated catalogue;
removed authority is not restored merely to make the reload appear atomic.
Callers must check the reload result. End-to-end acceptance must cover live
processes, cached connections and concurrent requests, not just fresh exec.

The temporary authority for `/etc/rc` is configured separately in
`/Capabilities/Config/switchboard/boot-authority.ucl`. Its endpoint allowlist and
attributes constrain the boot application, and its authority is revoked when
that boot phase ends. It is not a general grant for UID zero or login shells.

For a system image, policy and matching executable changes should be prepared
and tested together in a boot environment. A boot environment does not itself
make an untrusted executable safe: verifier enforcement, libraries, loaders,
configuration and resource isolation remain part of the integrity boundary.
See [Software Attributes](attributes.md).
