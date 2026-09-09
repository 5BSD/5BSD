# Rootless hardening

5BSD separates POSIX identity from capability authority, but the default
installation remains deliberately compatible and permissive: uid 0 and members
of `wheel` receive a full-discovery SYSTEM session. Ordinary users receive a
uid-scoped USER session. The installer can add administrator users and groups;
every added entry should be treated like an administrator credential.

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
