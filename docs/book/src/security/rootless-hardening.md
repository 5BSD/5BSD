# Rootless hardening

5BSD separates POSIX identity from capability authority, but the default
installation remains deliberately compatible and permissive: uid 0 and members
of `wheel` receive a full-discovery SYSTEM session. Ordinary users receive a
uid-scoped USER session. The installer can add administrator users and groups;
every added entry should be treated like an administrator credential.

## What “rootless” means

The compatible profile keeps root as a powerful administrator. It aims at the
workstation tradeoff associated with macOS—administration remains convenient
while higher policy can reserve selected resources—but 5BSD does not yet claim
equivalence to macOS System Integrity Protection or a signed system volume.

The root-resistant target is the property associated with iOS-style platform
security: obtaining uid 0 alone is insufficient to modify the trusted system,
manage protected core services, weaken enforcement, or authorize the next
boot. In 5BSD that authority belongs to explicit capabilities and a separate
recovery/update principal, not to a special uid.

This target is not the current shipped state. Removing root from the capability
administrator policy reduces its authority inside the live capability plane,
but the conventional BSD substrate still lets root make persistent changes.
The roadmap below lists the additional enforcement required before a deployment
can honestly claim durable root resistance.

The policy is `/Capabilities/Config/principal-policy.ucl`:

```ucl
admin {
    uids = [ 0 ];
    groups = [ "wheel" ];
}
```

User entries are numeric UIDs so renaming an account does not silently transfer
authority. Group entries are names and apply to the complete group membership
resolved by `authagentd`. Keep the list small, use a dedicated administrator
group when practical, and keep ordinary service accounts out of every listed
group.

Removing uid 0 or `wheel` from a valid policy prevents those principals from
receiving SYSTEM sessions. This is useful hardening, but it is not yet a durable
rootless boundary: conventional root can still edit the policy or installed
system and reboot. Recovery access must be tested before deploying a policy
that omits root.

## Root-resistance roadmap

The remaining platform work is explicit:

- **TODO: verified system dataset and signed pkgbase updates.** System binaries,
  capability bundles, the kernel, and platform policy must be mounted from a
  cryptographically verified or sealed ZFS boot environment. A normal root
  session must not be able to turn modified content into the next trusted boot.
- **TODO: separate recovery and update authority.** Changing the trusted system
  policy or selecting an unverified boot environment must require authority not
  available to an ordinary root shell, such as a recovery credential or
  hardware-backed owner authorization.

Until both items are implemented, 5BSD constrains root processes at runtime but
does not claim that a hostile root administrator cannot persistently replace the
system.
