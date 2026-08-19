# Capability Bundles (.cap Files)

A capability bundle is how a service ships on 5BSD: a self-contained
application directory whose manifest declares, up front, every
capability the service will ever hold. serviced verifies the
declaration, pre-acquires the kernel authority through mac_capability,
and starts the program already confined — the process never asks for
authority at runtime; it receives it.

## Bundle format

A bundle is a directory named `Name.cap`:

```
Name.cap/
    etc/svc.ucl        service manifests (one or more, UCL format)
    bin/program        executables
    resources/         optional data
```

Each manifest carries bundle metadata and a service definition. A real
example, `/usr/src/Capabilities/System/token-test.cap/etc/token-test.ucl`:

```ucl
bundle_id = "org.test.token-test";
version = "1.0";
author = "test";
program = "token-test";
provides = ["token-test"];
capabilities {
    paths = ["/usr/src/token-path-target"];
    files = [{ path = "/usr/src/token-file-target"; actions = "read"; }];
    network = [{
        domain = "inet"; protocol = "tcp"; port = 49152;
        direction = "bind"; address = "127.0.0.1";
    }];
}
```

The full manifest surface (see `struct svc_manifest` in
`/usr/src/lib/libcapbundle/serviced_manifest.h`) covers: program,
arguments, environment, user/group (default: the pkgbase `capability`
account), `provides` (up to 8 reverse-domain service names),
`components` (local authority replacements — currently `filesystem`
and `network`), `startup_after` ordering edges, restart policy
(never/always/on-failure), an optional jail to create and attach the
child into, and the capability declarations themselves: `paths`,
`files` (path + `FI_FS_*` action mask), `network` claims (domain,
protocol, port/range, direction, CIDR address), `jail` claims, `vsock`
claims, `storage` (TrustedZFS) claims, `services`, and a `system`
gate bitmask (`SYS_GATE_*`). Unknown fields fail closed.

## Install locations and discovery

serviced scans two directories at startup
(`/usr/src/usr.sbin/serviced/bundle_registry.c`):

```
/Capabilities/System/    system bundles (SERVICED_BUNDLE_DIR_SYSTEM_DEFAULT)
/Capabilities/           user bundles   (SERVICED_BUNDLE_DIR_USER_DEFAULT)
```

Both are overridable via the `SERVICED_BUNDLE_DIR_SYSTEM` and
`SERVICED_BUNDLE_DIR_USER` environment variables (used by the test
suites). A malformed bundle stops the scan rather than being silently
skipped.

## Validation: libcapbundle and servicectl

`/usr/src/lib/libcapbundle/` is the single parser/validator shared by
serviced and `servicectl`. `capbundle_open()` parses the directory,
`capbundle_verify()` checks structure, required fields, binary
existence, and internal consistency, and
`capbundle_check_startup_cycles()` rejects circular component-startup
dependencies across bundles. Operators validate a bundle before
deployment with `servicectl verify`. The library is documented in
`libcapbundle.3` and has its own test suite plus examples under
`/usr/src/lib/libcapbundle/`.

## Activation targets

The bundle registry reserves **every** name in `provides` and maps them
all to one bundle/service record before the provider process exists.
Any `service_connect(ctx, name, &fd)` for any reserved name launches
the record on demand; simultaneous requests for different names of one
bundle cannot create duplicate processes. The provider then claims each
listener (`NAME_CLAIM`), and serviced refuses `READY` until the complete
`provides` set is claimed and the provider has entered capability mode.
Names are activated individually (`ACTIVATE_NAME`) — each has its own
activation callback and result, so one name's failure leaves its
siblings available. A provider may expose only exact names from its
declaration, and the runtime identity is derived from bundle identity
plus program, not from the first `provides` entry.

## How services receive their capabilities

Declared capabilities become kernel authority before `exec`:

- **File, network, vsock, jail, and storage claims** are established
  through the mac_capability `isolation` service (and TrustedZFS for
  `storage`); enforcement is MACF-hook based and keyed to the process
  nonce.
- **System gates** arrive as narrowed gate tokens from the
  mac_capability `system` service.
- **Local components** (`filesystem`, `network`) are provider worker
  processes serviced enlists into the consumer's coalition; the
  consumer finds them as descriptor numbers in the `FILESYSTEMCMP` /
  `NETWORKCMP` bootstrap environment entries — descriptors, not names,
  and not globally discoverable.
- Component channels are non-transferable and locked against fork/exec
  propagation except for the one supervised exec serviced performs
  (see [Capability Transfer](capability-transfer.md)).

The FileSystem component additionally gives every consumer read-only
access to its own verified `.cap` bundle contents, alongside scratch
and persistent namespaces with durable quotas.

## Relationship to rc.d

The service architecture plan (`/usr/src/docs/service-architecture-plan.md`)
treats `.cap` bundles and rc.d scripts as nodes in one unit graph: an
rc.d script and a bundle providing the same name are the same node, and
migration means rewriting a script as a `.cap` bundle with identical
`provides`. Bundle directories live on the root filesystem so serviced
can sequence services before `/usr` mounts.

**Status.** The format, parser, registry, verification
(`servicectl verify` passes for all in-tree manifests — see
`/usr/src/docs/capability-components-validation.md`), and the
token-test fixture bundle are built and tested; the broader rc.d
migration described in the service architecture plan is ongoing design
work. `/usr/src/Capabilities/System/` in the source tree contains
only the `token-test.cap` test fixture — production bundles are
installed by the provider Makefiles at build time (e.g.
`/usr/src/usr.sbin/logd/Makefile` installs
`/Capabilities/System/Log.cap`, and
`/usr/src/usr.sbin/localfilesystem/Makefile` installs
`/Capabilities/System/LocalFilesystem.cap`).
