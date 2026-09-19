# Rootless hardening

5BSD separates POSIX identity from capability authority, but the default
installation remains deliberately compatible and permissive: the shipped
principal policy grants uid 0 and members of `wheel` every anointment (`*`)
with admin rights, so their sessions discover and connect to every SYSTEM and
CORE service. Ordinary users receive a uid-scoped session that holds no
anointment: it reaches every open endpoint and no gated one. The installer
can add administrator users and groups; every added entry should be treated
like an administrator credential. Holding every anointment does not grant
runtime management of CORE services: they cannot be stopped, restarted,
unloaded, or disabled, even by root or another capability administrator.

## Current security boundary

The installed system keeps root as a powerful compatibility administrator.
5BSD capability gates can reserve selected live operations from a root process,
but the installed system does not claim macOS System Integrity Protection, a
signed system volume, or iOS-style root resistance.

The policy is `/Capabilities/Config/principal-policy.ucl`:

```ucl
principals {
    admin {
        groups = [ "wheel" ];
        uids = [ 0 ];
        anointments = [ "*" ];
        admin_rights = true;
    }
    default {
        anointments = [];
    }
}
```

User entries are numeric UIDs so renaming an account does not silently transfer
authority. Group entries are names and apply to the complete group membership
resolved by `BSDAuth`. Keep the list small, use a dedicated administrator
group when practical, and keep ordinary service accounts out of every listed
group.

The stricter profile keeps the bypass but turns every gated reach into an
audited, per-command ask through `anoint(1)`:

```ucl
admin { groups = ["wheel"]; uids = [0]; anointments = [];
        may_elevate = ["*"]; admin_rights = true; }
```

Root can also be given a short list instead of `*`; the knobs are described
in [the principal policy](ipc-anointments.md#who-gets-what-at-login-the-principal-policy).

Removing uid 0 or `wheel` from a valid policy leaves those principals under
`default`, holding nothing. Removing them does not create a durable rootless
boundary: conventional root can still alter installed files and policy, then
reboot. Treat the setting as capability-plane least privilege, not as a system seal.
