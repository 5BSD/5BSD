# system.Crypto (BSDCrypto)

BSDCrypto is the cryptography broker of the capability plane. It mints
kernel-backed crypto session descriptors on request, so a unit gets
encryption, authentication, hashing, randomness, key exchange and signing
without ever holding key bytes or `/dev/crypto`. 5BSD has it because the
classic model, open the device and pass your key in, puts recoverable
plaintext keys in every process that needs crypto, and because a fixed
algorithm policy is easier to audit in one daemon than in every caller.

## What it brokers

The kernel side is `DTYPE_CRYPTO` (6 in `sys/sys/file.h`): a descriptor
wrapping one OpenCrypto session whose key material is generated inside the
kernel and never leaves it. The ABI is `sys/sys/cryptodesc.h`. A descriptor
carries a rights mask fixed at mint, `CRYPTODESC_RIGHT_ENCRYPT`,
`DECRYPT`, `AUTH`, `VERIFY`, `SIGN`, `EXCHANGE`, `DERIVE` (the first four
plus `DERIVE` are `CRYPTODESC_RIGHT_SESSION`), an optional TTL, and a
state (`CRYPTODESC_STATE_REVOKED`, `EXPIRED`, `KEY_INVALID`). Rights only
shrink: `CIOCSCRYPTODESCRIGHTS` restricts to a subset, `CIOCCRYPTODESCREVOKE`
disables the descriptor permanently, expiry does the same on a timer, and
`CIOCCRYPTODESCDERIVE` yields an HKDF-SHA256/512 child whose authority and
lifetime are clamped to its parent's. Named volatile keys
(`CIOCGCRYPTONAMEDKEY`, `NAMEDLEASE`, `NAMEDROTATE`, `NAMEDDELETE`,
`NAMEDSTAT`, `NAMEDLIST`) are kernel-resident symmetric templates scoped to
an owner string, with generation numbers, and are lost on module unload by
design; there is no import, export or persistence ABI. X25519 exchange and
Ed25519 signing come from `CIOCGCRYPTOKEYDESC`, `CIOCCRYPTX25519`,
`CIOCCRYPTOSIGN` and `CIOCCRYPTOVERIFY`. A holder learns about attenuation,
revocation, expiry, and rotation or deletion of the backing named key
through `EVFILT_CRYPTODESC` (-17) with the `NOTE_CRYPTODESC_RIGHTS`,
`REVOKE`, `EXPIRE`, `KEY_ROTATE` and `KEY_DELETE` hints. The sysctls
`kern.crypto.cryptokey_objects`, `cryptokey_max_objects` and
`cryptokey_max_owner_objects` bound the named-key store.

BSDCrypto is the policy boundary in front of those ioctls. It starts as
root so the kernel records `PRIV_DRIVER` on its `/dev/crypto` control
descriptor (named-key creation needs it), loads the `cryptodev` module
through [system.SystemExtension](extension.md) if it is not built in, opens
the device under the delivered `/dev`, applies `SERVICE_PROTECT_NOPRIVS`
and `NOEXEC`, and serves from capability mode. Each accepted client gets a
`pdfork(2)` worker that adopts the channel, enters capability mode, drops
inherited authority, and keeps exactly one kernel handle: the control
descriptor, limited to `CAP_IOCTL` and an eight-command allowlist. The
worker fills the named-key owner from the client's channel label, never
from the wire, so one label can never name, lease, rotate, delete, stat or
list another label's keys. A reclaim child enumerates owners with
`CIOCGCRYPTOOWNERLIST` every `CRYPTO_RECLAIM_INTERVAL` seconds and drops the
keys of bundles that are neither installed nor running.

## Unit

| Field | Value |
|---|---|
| Wire name | `system.Crypto` |
| Bundle | `/Capabilities/System/Crypto.cap` (`bundle_id = "system.Crypto"`, version 3.1.0) |
| Program | `Units/bsdcrypto.unit/bin/BSDCrypto` |
| Unit name | `bsdcrypto` |
| Activation | `boot = true`, `ipc = ["system.Crypto"]` |
| User | `root` (for `PRIV_DRIVER` at `/dev/crypto` open; `NOPRIVS` afterwards) |
| Launch mode | born in capability mode; `directories = ["/dev", "/Capabilities/System", "/Capabilities/Apps", "/Capabilities/Run/live"]` |
| Declared gates | none (module load is self-served over `system.SystemExtension`) |
| Visible | default (system-domain lookups only) |
| Control | `system` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 512`, `nproc = 1024`, `core = 0`; `umask = "0077"` |

The `nproc` limit counts every process with the same real uid, so it must
cover the other root daemons. A failed startup exits with a code from 10
to 21 naming the step (11 is the cryptodev extension, 13 the control
device, 20 capability mode), listed in BSDCrypto(8).

## Wire operations

The protocol is `lib/libcryptocmp/cryptocmp_protocol.h`: magic
`CRYPTOCMP_MAGIC`, `CRYPTOCMP_VERSION` 3, interface version `3.3.0`. Every
message starts with an 8-byte-aligned `cryptocmp_msg` (magic, version,
opcode, status). A descriptor rides back as the reply's SCM_RIGHTS fd.

| Op | Request | Reply | Errors |
|---|---|---|---|
| 1 GENERATE | `cryptocmp_generate` (cipher, mac, keylen, mackeylen, rights, ttl, flags, crid, ivlen, maclen) | header + fd (session descriptor) | `EINVAL` (out of policy), the errno from the kernel mint |
| 2 GENERATE_KEY | `cryptocmp_key_generate` (type X25519 or Ed25519, rights, ttl, flags) | `cryptocmp_key_reply` (32-byte public key) + fd | `EINVAL` |
| 3 NAMED_CREATE | `cryptocmp_named_create` (name[64], generate params) | `cryptocmp_named_reply` (generation) | `EINVAL` (name charset), `EEXIST`, `ENOSPC` (owner or global cap) |
| 4 NAMED_LEASE | `cryptocmp_named_lease` (name, rights, ttl, flags) | `cryptocmp_named_reply` + fd | `ENOENT`, `EINVAL` |
| 5 NAMED_ROTATE | `cryptocmp_named_control` (name) | `cryptocmp_named_reply` (new generation) | `ENOENT` |
| 6 NAMED_DELETE | `cryptocmp_named_control` (name) | `cryptocmp_named_reply` | `ENOENT` |
| 7 DIGEST | `cryptocmp_digest` (alg SHA2-256/384/512, ttl, flags) | header + fd (`CSP_MODE_DIGEST` session with `RIGHT_AUTH`) | `EINVAL` |
| 8 RANDOM | `cryptocmp_random` (nbytes, at most 1024) | `cryptocmp_random_reply` (nbytes, data) | `EINVAL` |
| 9 NAMED_STAT | `cryptocmp_named_stat` (name) | `cryptocmp_named_stat_reply` (`cryptocmp_named_info`: generation, rights, cipher, mac, keylen, mackeylen) | `ENOENT` |
| 10 NAMED_LIST | `cryptocmp_named_list` (cursor, flags) | `cryptocmp_named_list_reply` (count, `next_cursor`, up to 16 entries of name, generation, rights) | none; an out-of-range cursor is an empty page |
| 11 HELLO | header (magic + version, no body) | header, status 0 | version mismatch |

HELLO was added as opcode 11 rather than 1 so no existing opcode moved;
`cryptocmp_open(3)` sends it first, and a mismatched pair fails at open.
Rotating or deleting a named key invalidates every outstanding lease and
its derived lineage, which the holders observe as `NOTE_CRYPTODESC_KEY_*`.

## Client library

libcryptocmp(3) (`<cryptocmp.h>`, `-lcryptocmp`) is the consumer API:

| Group | Functions |
|---|---|
| Session | `cryptocmp_open(struct cryptocmp_client **)`, `cryptocmp_close` |
| Minting | `cryptocmp_generate(client, const struct cryptocmp_generate *, int *fd)`, `cryptocmp_generate_key(client, const struct cryptocmp_key_generate *, uint8_t public_key[32], int *fd)`, `cryptocmp_digest(client, alg, ttl, flags, int *fd)` |
| Randomness | `cryptocmp_random(client, void *buf, size_t nbytes)` |
| Named keys | `cryptocmp_named_create(client, name, params, uint64_t *gen)`, `cryptocmp_named_lease(client, name, rights, ttl, uint64_t *gen, int *fd)`, `cryptocmp_named_rotate`, `cryptocmp_named_delete`, `cryptocmp_named_stat(client, name, struct cryptocmp_named_info *)`, `cryptocmp_named_list(client, cursor, entries, max, uint32_t *count, uint32_t *next_cursor)` |

The returned fd is driven with the ordinary OpenCrypto `CIOCCRYPT` family;
what it may do is its rights mask. libcryptodesc(3) (`<cryptodesc.h>`,
`-lcryptodesc`) is the thin ioctl wrapper the broker itself uses and a
tool author may use on a descriptor it already holds: `cryptodesc_mint`,
`cryptodesc_mint_generated`, `cryptodesc_mint_key`, the `cryptodesc_named_*`
family (which take an explicit `owner`), `cryptodesc_owner_list`,
`cryptodesc_restrict`, `cryptodesc_revoke` and `cryptodesc_get_info` (which
fills a `cryptodesc_info` with type, rights, state, provider, expiry and
generations). Only the mint and named functions need the control fd; the
last three work on any crypto descriptor.

A unit that leases a named key and narrows the lease before handing it to
a helper:

```c
#include <err.h>
#include <unistd.h>
#include <cryptocmp.h>
#include <cryptodesc.h>

static int
lease_encrypt_only(const char *name)
{
        struct cryptocmp_client *client;
        uint64_t generation;
        int fd;

        if (cryptocmp_open(&client) != 0)
                err(1, "system.Crypto");
        if (cryptocmp_named_lease(client, name,
            CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT, 600,
            &generation, &fd) != 0)
                err(1, "lease %s", name);
        cryptocmp_close(client);
        if (cryptodesc_restrict(fd, CRYPTODESC_RIGHT_ENCRYPT) != 0)
                err(1, "restrict");
        return (fd);            /* encrypt-only, expires in 600 s */
}
```

Link with `-lcryptocmp -lcryptodesc`.

## Command-line tool

There is no ctl tool. A descriptor's state can be inspected from a program
with `cryptodesc_get_info(3)`, and procstat(1) shows the descriptor type.
The broker's `crypto` DTrace provider exports `named-list` (owner, entry
count, result); key names and material are never probe arguments.

## Policy

Policy is compiled into `usr.sbin/BSDCrypto/policy.c`, not read from a
file, and is validated before any request reaches the kernel. It fixes the
algorithm profiles: AES-CBC, AES-GCM-16, ChaCha20-Poly1305,
XChaCha20-Poly1305, AES-XTS and DEFLATE for ciphers; HMAC-SHA2-256/384/512
for MACs; SHA2-256/384/512 for DIGEST. It enforces exact key, IV and tag
lengths per algorithm, checks AEAD cipher and MAC pairing (AES-GCM,
ChaCha20-Poly1305 and XChaCha20-Poly1305 are the AEAD set), requires
encrypt and authenticate rights to be granted as matched pairs so a
misleading descriptor cannot be minted, bounds every TTL to 86400 seconds,
requires `flags` to be zero where unused, and restricts named-key names to
`A-Z`, `a-z`, `0-9`, `.`, `_` and `-`. The
per-request flag `CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY` narrows a
request to AES-CBC, AES-GCM and HMAC-SHA2; it is a selection guardrail, not
a FIPS 140 validation claim, and `docs/book/src/providers/crypto.md`
states the boundary exactly. Owner scoping is not a policy entry but an
invariant: the owner is the channel label. There is no admin bypass and no
per-label allow-list; any unit that can resolve `system.Crypto` may mint
within the profile set, and every request is audited through
[system.Audit](audit.md) as `AUE_CRYPTOCMP_POLICY` (43334), metadata only.

## Tests

| Suite | Location | Installed under | What it proves |
|---|---|---|---|
| `policy_test` (24), `provider_test` (28), `bundle_test.sh` | `usr.sbin/BSDCrypto/tests` | `/usr/tests/usr.sbin/BSDCrypto` | every profile rule and rejection, the worker path under `BSDCRYPTO_TESTING` (mint, lease, rotate-invalidates-lease, owner isolation, reclaim), the installed bundle |
| `cryptocmp_api_test` (6), `client_protocol_test` (16) | `lib/libcryptocmp/tests` | `/usr/tests/lib/libcryptocmp` | wire encoding of all eleven ops against `fake_service`, HELLO at open |
| `cryptodesc_api_test` (6) | `lib/libcryptodesc/tests` | `/usr/tests/lib/libcryptodesc` | the ioctl wrappers |
| `cryptodesc_test` (17) | `tests/sys/opencrypto` | `/usr/tests/sys/opencrypto` | the kernel: rights attenuation, revoke, expiry, HKDF known answers, named-key generations, `EVFILT_CRYPTODESC` |

Run with `kyua test -k /usr/tests/usr.sbin/BSDCrypto/Kyuafile`; packages
`5BSD-bsdcrypto-tests`, `5BSD-libcryptocmp-tests`,
`5BSD-libcryptodesc-tests`. The kernel test needs `cryptodev` loaded or
built in; on the 5BSD kernel it is built in.

## Status and gaps

Shipped and VM-verified: the descriptor type, named volatile keys, HKDF
derivation, X25519 and Ed25519, the broker with all eleven ops, the
NIST-approved-only gate, and key reclaim on bundle removal. The system was
disabled for a time because `cryptodev` was a loadable module the plane
could not load early enough; making it static resolved that. Open findings:
`cryptodesc_named_list(3)` drops the tail of a kernel page when the
caller's `max` is below `CRYPTODESC_NAMED_LIST_MAX` (inventory section 14,
finding 4); there is no cryptodesc(4) or cryptodesc(9) manual page for the
kernel ABI, only libcryptodesc(3); RSA, ECDSA and certificate validation
are design-only (`docs/book/src/providers/crypto.md`). BSDCrypto runs as
root for the `PRIV_DRIVER` snapshot and is on the list of providers to move
to a gate-based launch. This is not a key vault and there is no plan to
add one: persistence would put recoverable keys outside the kernel.
