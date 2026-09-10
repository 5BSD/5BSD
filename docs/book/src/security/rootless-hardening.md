# Rootless hardening

5BSD separates POSIX identity from capability authority, but the default
installation remains deliberately compatible and permissive: uid 0 and members
of `wheel` receive a SYSTEM session that can discover and connect to SYSTEM and
CORE services. Ordinary users receive a uid-scoped USER session. The installer
can add administrator users and groups; every added entry should be treated
like an administrator credential. A SYSTEM session does not grant runtime
management of CORE services: they cannot be stopped, restarted, unloaded, or
disabled, even by root or another capability administrator.

## Current security boundary

The installed system keeps root as a powerful compatibility administrator.
5BSD capability gates can reserve selected live operations from a root process,
but the installed system does not claim macOS System Integrity Protection, a
signed system volume, or iOS-style root resistance.

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
receiving SYSTEM sessions. Removing them does not create a durable rootless
boundary: conventional root can still alter installed files and policy, then
reboot. Treat the setting as capability-plane least privilege, not as a system seal.
