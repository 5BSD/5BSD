# A Per-User Agent

A per-user agent is a long-running program that one user owns: switchboard
launches it, supervises it and restarts it, the owner starts and stops it
without an operator, and it can never grow into a system service by asking.
5BSD has them so that users get supervision and the plane's discovery without
being handed root, and so that a user's unverified code is confined by
construction rather than by review. This chapter explains what the management
model gives a user, the manifest fields that matter, how the agent is loaded
and launched, what it cannot do, and ends with a notifier that consumes
`system.Notify`. The example compiles against the tree and its bundle passes
`switchboardctl verify`.

## What a user gets

The management model has three classes, selected by the manifest key
`control`. They govern who may stop, restart, unload or disable a unit at
runtime, and they are checked before any privilege:

| Class | Who manages it | Typical units |
|---|---|---|
| `core` | nobody, not even root; only the boot and shutdown lifecycle | switchboard's essentials, BSDTime |
| `system` | a session holding operator authority (`admin_rights` in `principal-policy.ucl`) | base providers, adopted rc.d services, site bundles |
| `user` | the owning uid, or an operator | per-user agents |

For a user this means three things. **Load**: a bundle dropped into the
user's agent root is loaded by switchboard without any operator action.
**Confine**: whatever the bundle declares, switchboard forces the class and
the domain, so the agent lives inside its owner's world. **Self-service
control**: `switchboardctl start`, `stop` and `restart` on the agent's label
succeed from the owner's own session, because the control connection carries
the principal `system.Auth` recorded when it minted the session and
`management.c` compares it with the owning uid. There is no sudo step and
nothing for an operator to grant. The model as a whole is in
[The Management Model](../plane/management-model.md).

## The agent root

Each user has an agent root at `/Capabilities/Users/<uid>/Agents`.
switchboard creates it on demand the first time that user's session reaches
the plane: `/Capabilities/Users` stays root-owned, the per-uid directory and
its `Agents` are chowned to the user so the user can populate them. Trust is
rooted in that ownership: at scan time `/Capabilities/Users/<uid>` must be a
directory owned by the uid, `Agents` must be a directory, and every bundle
tree under it is verified the way system bundles are, except that the
expected owner is the user rather than root. A mis-owned entry, a non-numeric
directory name or a missing `Agents` is skipped silently; a user's files can
never fail the plane's convergence.

```sh
$ id -u
1001
$ ls -ld /Capabilities/Users/1001 /Capabilities/Users/1001/Agents
drwxr-xr-x  3 alice  wheel  ... /Capabilities/Users/1001
drwx------  3 alice  wheel  ... /Capabilities/Users/1001/Agents
$ ls /Capabilities/Users/1001/Agents
Notifier.cap
```

## The manifest

A per-user bundle has the same `Bundle.ucl` and `Unit.ucl` as any other. The
fields that matter for an agent:

| Key | Value for an agent | What switchboard does with it |
|---|---|---|
| `control` | `"user"` | forced to `user` whatever is written |
| `domain` | `"user"` | forced to `user`: the agent resolves only user-visible names |
| `visible` | omit | dropped: an agent's `ipc` names are not resolvable from user sessions |
| `level` | `"background"` or `"standard"` | `interactive` is a privilege and is clamped to `standard` |
| `user` | the owner's login name | the uid the program runs as; the default is `capability`, so set it |
| `activation` | `boot = true`, `timer`, `schedule`, `path`, ... | as for any unit |
| `restart`, `limits`, `umask`, `protect`, `watchdog` | as needed | as for any unit |
| `ambient`, `mint_authority`, `capabilities` | omit | cleared: an agent is always born in capability mode and holds no gate |

The manifest for the notifier:

```ucl
# Notifier.cap/Bundle.ucl
schema = "org.5bsd.capability-bundle";
schema_version = 1;
bundle_id = "org.example.notifier";
version = "1.0.0";
sequence = 1;
publisher = "org.example";
units = ["notifier"];

# Notifier.cap/Units/notifier.unit/Unit.ucl
activation { boot = true; }
restart = "on-failure";
control = "user";
domain = "user";
level = "background";
user = "alice";
limits { nofile = 64; nproc = 8; core = 0; }
```

Writing `control = "user"` and `domain = "user"` explicitly is good manners
rather than necessity; switchboard would set them anyway. The `user` line is
not optional in practice: the manifest default is the `capability` account,
and the launch resolves whatever `user` names with `getpwnam(3)`, so an agent
that wants to run as its owner says so.

## How it is launched

switchboard builds its bundle registry at start-up and on every reload, and
that scan includes the per-user roots. An agent with `boot = true` is
launched during convergence like any boot unit; one with a `timer`,
`schedule`, `path` or `queue_directory` activation is launched on demand when
its source fires. The launch is the ordinary born-in-capability-mode launch:
`cap_enter(2)` in the child, `fexecve(2)` of the bundle program, libraries and
`Config/` by descriptor, stdio to `/var/log/capability.log`, and RUNNING when
the kernel reports the seal. See
[Capability Mode and the Born-Sandboxed Launch](../capability/capability-mode-and-launch.md).

Two consequences follow from "at start-up and on reload". First, an agent is
not tied to a login session: it runs while the machine is up, whether or not
its owner is logged in, and it has no controlling terminal or session
environment. Second, a bundle dropped into the agent root after boot is not
noticed until the next reload. switchboard's directory watch covers
`/Capabilities/System` and `/Capabilities/Apps`, not the per-user roots, and
`switchboardctl reload` needs the `system.switchboard.admin` anointment. Until
that changes, a new agent appears at the next reboot or when an operator
reloads.

Once loaded, the agent is listed and controlled by its label,
`bundle_id/unit`:

```sh
$ switchboardctl services
...
  org.example.notifier/notifier running  pid 1187 restart=on-failure mgmt=user by=system
$ switchboardctl stop org.example.notifier/notifier
stop: "org.example.notifier/notifier" stopping
$ switchboardctl start org.example.notifier/notifier
start: "org.example.notifier/notifier" starting
```

The same commands from another user's session are refused with
`permission denied`, logged, and audited as `AUE_SWITCHBOARD_CTL`.

## What it cannot do

| Wanted | Result |
|---|---|
| Resolve `system.Network` or another SYSTEM-only name | `ENOENT`; the agent's domain is `user` |
| Publish a name other units resolve | its `visible` is dropped, so user sessions cannot resolve it and its domain cannot reach system ones |
| Mint a session for another uid | `mint_authority` is cleared |
| Hold a system gate (`settime`, `sysctl`, ...) | the `capabilities` block is stripped |
| Run outside capability mode | `ambient` is cleared |
| Take the interactive scheduling boost | clamped to `standard` |
| Be managed by anyone but its owner or an operator | `EPERM` from the class gate |
| Escape its owner's container | storage is derived from its own label |

The point of the list is that none of it depends on what the bundle says
about itself. A user who writes `control = "core"` gets `user`; a user who
writes `capabilities { system = ["settime"]; }` gets nothing.

## Example: a user-scoped notifier

The agent subscribes to a topic on `system.Notify`, the pub/sub broker, and
records every publication through `system.Log`. Both names are
`visible = ["user"]`, which is why a `user`-domain agent can reach them. The
open tier of BSDNotify lets every session subscribe to anything and publish
under `user.*`; the gated tier, `system.Notify.System`, needs an anointment
an agent does not hold.

```c
#define NOTIFIER_TOPIC     "user.example.notifier"
#define NOTIFIER_WAIT_MS   30000

static struct notify_client *
notify_get(void)
{
        struct notify_client *client;

        if (notify_client_open(&client) == -1) {
                logcmp_log(LOG_WARNING, "system.Notify unavailable: %m");
                return (NULL);
        }
        if (notify_subscribe(client, NOTIFIER_TOPIC) == -1) {
                logcmp_log(LOG_WARNING, "subscribe %s: %m", NOTIFIER_TOPIC);
                notify_client_close(client);
                return (NULL);
        }
        return (client);
}

int
main(void)
{
        union { struct notify_event ev; unsigned char raw[NOTIFY_MAX_MESSAGE]; } u;
        struct notify_client *client = NULL;
        ssize_t got;

        for (;;) {
                if (client == NULL && (client = notify_get()) == NULL) {
                        sleep(5);               /* provider down: retry later */
                        continue;
                }
                got = notify_next(client, &u.ev, sizeof(u), NOTIFIER_WAIT_MS);
                if (got == -1) {
                        if (errno == ETIMEDOUT || errno == EAGAIN)
                                continue;
                        logcmp_log(LOG_WARNING, "notify_next: %m");
                        notify_client_close(client);
                        client = NULL;
                        continue;
                }
                if (u.ev.type != NOTIFY_EVENT_PUBLISH)
                        continue;
                logcmp_log(LOG_INFO, "from %.*s on %.*s: %.*s",
                    (int)u.ev.publisher_length, (const char *)u.ev.data,
                    (int)u.ev.topic_length,
                    (const char *)u.ev.data + u.ev.publisher_length,
                    (int)u.ev.payload_length,
                    (const char *)u.ev.data + u.ev.publisher_length + u.ev.topic_length);
        }
}
```

`notify_next()` blocks up to the given timeout for the next event and copies
it, variable-length, into the caller's buffer: publisher, topic and payload
follow the header back to back. `NOTIFY_EVENT_GAP` and `NOTIFY_EVENT_RESET`
tell a subscriber it missed something, so a real agent re-reads its state
cells (`notify_state_get()`) when it sees them. The library reconnects on a
lost connection by itself; the loop above adds the one thing it cannot know,
which is how long to wait before trying again. Publishing from a shell to
exercise it:

```sh
$ notifyctl publish user.example.notifier "hello from alice"
$ logctl show info
```

Topics are dotted names, letters and digits, no leading digit in a segment;
the shipped policy is in `usr.sbin/BSDNotify/capbundle/bsdnotify.conf` and
the op set in [system.Notify](../providers/notify.md).

## Building the bundle

```sh
$ cc -o notifier notifier.c -lservice -llogcmp -lnotify
$ mkdir -p Notifier.cap/Units/notifier.unit/bin
$ cp notifier Notifier.cap/Units/notifier.unit/bin/
$ switchboardctl verify Notifier.cap
...
  [0] org.example.notifier/notifier
      activation: boot
      restart:   on-failure
      management: user
$ cp -R Notifier.cap /Capabilities/Users/$(id -u)/Agents/
```

`switchboardctl verify` runs with no plane and no root; it reports the
effective view as switchboard will read it, before the per-user forcing is
applied. If the agent root does not exist yet, the session has not opened
the control plane since boot; running `switchboardctl services` once is
enough to make switchboard create the directories.

## Limits

The per-user root is not watched, so loading a new agent needs a reload or a
reboot. An agent's `ipc` names are not resolvable from its owner's session,
which makes agents consumers rather than providers today. And there is no
per-session lifetime: an agent that should run only while its owner is logged
in has to notice that itself.
