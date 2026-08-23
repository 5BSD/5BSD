# Service Manifests

5BSD services and their capability grants are declared in UCL manifests.
There are two manifest surfaces in the base system: **capability bundles**
(`.cap` directories consumed by `serviced`) and the **tzfsd configuration
with its `conf.d`-style drop-ins** (consumed by the TrustedZFS storage
broker). Both use libucl syntax; both are parsed before the consuming
daemon enters capability mode.

> A note on stray files: the `*.plist` files sometimes seen at the top of
> a 5BSD source tree (`broker.plist`, `att.plist`, …) are clang static
> analyzer output, not manifests, and nothing installs or reads them.
> Likewise `activation-target` is a test fixture from the serviced ATF
> suite. Neither is part of the manifest system.

## Capability bundles (`.cap`)

A capability bundle is a directory named `Name.cap` with a fixed layout:

```
Log.cap/
├── bin/logd          # executables
└── etc/svc.ucl       # one or more service manifests
```

Bundles install into two registries scanned by `serviced`:

- `/Capabilities/System` — base-system bundles, installed by the build
  (for example `usr.sbin/logd/Makefile` installs `Log.cap`; `bsdnotify`
  and `localnetwork` follow the same pattern).
- `/Capabilities` — user/site bundles.

`serviced` scans both directories once at startup (`bundle_registry_init()`
in `usr.sbin/serviced/bundle_registry.c`), parses every `*.ucl` under each
bundle's `etc/`, and builds a table mapping provided service names to
bundles. Programs are **not** started at scan time: all public named
services are launched on first connection (scan-at-boot, exec-on-demand).
Before a bundle is accepted, `trusted_tree()` walks it with `fts(3)` and
rejects symlinks, non-regular files, and anything not root-owned or
group/world-writable.

### Manifest schema

The format is specified in `serviced(5)` (`usr.sbin/serviced/serviced.5`).
Top-level keys:

| Key | Meaning |
|---|---|
| `schema`, `schema_version` | `org.5bsd.serviced.service`, `1.0.0` |
| `bundle_id` | required, globally unique reverse-DNS id |
| `version`, `author` | metadata |
| `program` | required; name under `bin/` (absolute paths and `..` rejected) |
| `arguments`, `environment` | exec parameters |
| `user`, `group` | credentials (default `capability`) |
| `provides` | service names this manifest serves (max 8) |
| `components` | `filesystem` and/or `network` helper components |
| `restart` | `never` / `on-failure` / `always` |
| `stop_timeout`, `max_failures` | supervision limits |
| `kmod_requires` | kernel modules to load first |
| `jail` | `name` / `path` / `hostname` / `ip4_addr` |
| `capabilities` | grant groups: `paths`, `files`, `network`, `jails`, `vsock`, `services`, `system` |

Unknown keys are **errors** — a serviced manifest that misspells a key
fails to load. Parsed limits live in
`lib/libcapbundle/serviced_manifest.h` (up to 256 services per registry).

The smallest real in-tree manifest,
`usr.sbin/bsdnotify/capbundle/bsdnotify.ucl`:

```ucl
schema = "org.5bsd.serviced.service";
schema_version = "1.0.0";
bundle_id = "org.5bsd.Notify";
version = "1.0.0";
author = "5BSD";

program = "bsdnotify";
provides = ["org.5bsd.notify"];
restart = "on-failure";
user = "capability";
```

### Worked example: a capability-granting manifest

The test bundle `Capabilities/System/token-test.cap` (an ATF fixture, not
shipped) shows the `capabilities` block in full:

```ucl
bundle_id = "org.test.token-test";
version = "1.0";
author = "test";
program = "token-test";
provides = ["token-test"];
capabilities {
    paths = ["/usr/src/token-path-target"];
    network = [{
        domain = "inet";
        protocol = "tcp";
        port = 49152;
        direction = "bind";
        address = "127.0.0.1";
    }];
}
```

When a client first connects to the `token-test` service, `serviced`
launches `bin/token-test` as the `capability` user with only these
grants; the paths and socket permissions become usable once the delivered
capability tokens are activated by the program.

## tzfsd configuration and flavor drop-ins

The TrustedZFS broker `tzfsd(8)` reads its main configuration from
`/etc/capability/tzfsd.ucl`, then overlays every `*.ucl` fragment in
`/etc/capability/tzfsd.d/` in lexical (`alphasort`) order — drop-ins
layer last and override the main file. A missing directory or file is
not an error, and unlike serviced manifests, **unknown keys are ignored**
so the schema can grow. Loading happens before `cap_enter()`.

Flavors are declared under a `flavors { <name> { … } }` object with the
keys `build` (`live` | `baked` | `source`), `source` (path to a ZFS send
stream or rootfs), `enabled`, and `default`. Only the `empty` and
`native` flavors are built into the broker; OS flavors ship separately
in the `tzfs-flavors` package (`usr.sbin/tzfs-flavors/`), whose entire
drop-in, installed as `/etc/capability/tzfsd.d/flavors.ucl`, is:

```ucl
flavors {
    linux {
        build = "baked"
        source = "/usr/share/tzfs/rocky9.zfs.zst"
        default = true
    }
    freebsd {
        build = "baked"
        source = "/usr/share/tzfs/freebsd.zfs.zst"
    }
}
```

Baked artifacts are produced by `/usr/libexec/tzfs-flavor-linux.sh` and
`tzfs-flavor-freebsd.sh` (wrappers over `tzfs-mkflavor.sh`) into
`/usr/share/tzfs/`. A flavor whose artifact is absent is simply not
offered — tzfsd logs a notice and a request for it returns `ENOENT`.

See `serviced(5)`, `serviced(8)`, `tzfs.conf(5)`, and `tzfs-flavors(7)`
for the authoritative schemas.

**Status:** `lib/libcapbundle` also documents a legacy non-bundle
manifest parser; the bundle path described here is the supported one.
