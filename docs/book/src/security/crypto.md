# Cryptographic Services

5BSD delivers cryptography to services as **capability descriptors, not
key bytes**. The `system.Crypto` capability service fronts the kernel
OpenCrypto framework: a service links `libcryptocmp`, which connects to
`system.Crypto` at first use over `service_connect()`, and obtains
descriptor-bound crypto sessions from the provider. What comes back is a
`DTYPE_CRYPTO` file descriptor — never raw key material.

## Component architecture

The kernel descriptor is independent of the provider. Its session
algorithms and `CRYPTODESC_RIGHT_*` operation mask are immutable at
mint time, it is passable over `SCM_RIGHTS`, and its final close tears
down the OpenCrypto session and clears retained key copies.
`/dev/crypto` remains the compatibility control interface;
`CIOCGCRYPTODESC` mints from caller-supplied keys, while
`CIOCGCRYPTODESCGENERATE` creates the key material wholly inside the
kernel.

The `localcrypto` provider (`usr.sbin/localcrypto/`) owns the
`/dev/crypto` control descriptor and asks the kernel to generate
separate cipher and MAC keys before minting the requested
rights-limited descriptor — the worker never holds the key bytes, and
no application ever receives the control descriptor. The provider is a
deliberate policy boundary, not a raw `/dev/crypto` proxy; its accepted
profiles (`usr.sbin/localcrypto/policy.c`) are:

- AES-CBC (128/192/256-bit keys, 16-byte IV)
- AES-GCM-16 (96-bit nonce, 16-byte tag)
- ChaCha20-Poly1305 and XChaCha20-Poly1305 (standard nonces, 16-byte tag)
- AES-XTS (256/512-bit combined keys, 16-byte tweak)
- HMAC-SHA-256/384/512
- DEFLATE compression

Requests are capped at 64-byte cipher and MAC keys; callers may select
the default, software, or hardware OpenCrypto class but cannot name an
arbitrary driver ID. Encrypt/authenticate and decrypt/verify rights are
paired for authenticated profiles, so an encrypt-without-tag or
decrypt-without-verify descriptor cannot be minted. Unsupported
primitives fail `EPROTONOSUPPORT`; malformed profiles fail `EINVAL`.

Named-key create, lease, rotate, and delete require descriptor authority
recorded when `/dev/crypto` is opened. The kernel does not re-check the
credentials of each later ioctl, so intentionally passing an already-open
privileged control fd delegates that authority; opening the device without
`PRIV_DRIVER` never acquires it. `localcrypto` therefore makes its control fd
non-transferable, locks it against fork and exec, limits it to `CAP_IOCTL`, and
installs the exact six-command allowlist needed for generated descriptors and
named-key lifecycle before entering capability mode.

Descriptors support **monotonic authority reduction**:
`CIOCSCRYPTODESCRIGHTS` lets a receiver drop operation rights before
passing a descriptor on, never restore them; `CIOCCRYPTODESCREVOKE`
permanently disables a descriptor (subsequent operations fail `EACCES`).
Descriptors may carry a TTL, after which every operation fails `ESTALE`.
`CIOCCRYPTODESCDERIVE` implements RFC 5869 HKDF-SHA-256/512 and returns
another opaque descriptor, never derived bytes. A parent must hold both
`DERIVE` and every right requested for the child, so derivation cannot create
authority. HKDF input is the complete cipher-plus-MAC secret, the child TTL is
clamped to the parent's remaining lifetime, and a child of a named lease
remains bound to the same generation so rotation or deletion revokes the
entire derived lineage. Every component request
is audited through the standard `Audit.cap` capability via `libauditcmp`
(client label, operation, result — no key material); audit-broker
failure is non-authoritative and can never widen a grant.

## Key lifecycle (KeyVault integration)

There is deliberately **no separate KeyVault device, daemon, or
library** in the tree — a second key authority with a file- or
UCL-backed store would expose recoverable plaintext keys outside the
kernel boundary. The useful KeyVault patterns (per-descriptor
attenuation, revocation, HKDF, expiry, X25519/Ed25519) were reworked
directly into `DTYPE_CRYPTO` after the upstream reference (revision
`172e3d6`) failed runtime evaluation.

Instead, `[CRYPTO]` owns **named volatile symmetric key objects**:
kernel-resident keys created under a declared algorithm/usage policy,
bound to the serviced client label (no global namespace), and leased as
ordinary short-lived, rights-reduced descriptors. Rotation bumps the
object generation so older leases fail `EACCES`; deletion does the same
and removes the name. The objects do not survive module unload or
reboot, and each create/lease/rotate/delete attempt — including denials
— emits a trusted audit event. The current implementation intentionally
has no import, export, persistence, or restart-recovery ABI; any future
persistence design requires a separately reviewed kernel-mediated
wrapping boundary.

Named objects are bounded by `kern.crypto.cryptokey_max_objects` (16384 by
default) and `kern.crypto.cryptokey_max_owner_objects` (1024 per service owner
by default). The read-only `kern.crypto.cryptokey_objects` counter exposes
current global use. Quota reservation and release are serialized with the
named-key registry, so concurrent creates cannot exceed either ceiling.

```text
consumer -- named-key request --> [CRYPTO] -- policy/key lookup --> kernel key object
consumer <-- DTYPE_CRYPTO fd ---- [CRYPTO] <-- scoped lease ----- kernel key object
                                      |
                                      +-- OpenCrypto session --> OpenCrypto
```

## Asymmetric support

`localcrypto` mints typed X25519 and Ed25519 descriptors today: X25519
descriptors permit only key `EXCHANGE`; Ed25519 descriptors carry
independently attenuable `SIGN` and `VERIFY` rights. Kernel tests cover
operation, rights attenuation, invalid signatures, and concurrent use,
with RFC 5869 as the HKDF known-answer vector.

**Status:** the broader asymmetric extension
(`docs/crypto-asymmetric-design.md`) — RSA-PSS and ECDSA sign/verify,
public-key import/export, certificate and chain parsing, and
trust-anchor validation — is designed but not built. The design keeps
`DTYPE_CRYPTO` typed (no untyped certificate handle), binds each
descriptor to algorithm, curve/size, operation, service identity, key
version, and expiry, and requires explicit hostname/time/EKU/revocation
policy for validation. Private key bytes never cross the component
boundary; certificate and public-key data may.

## Compliance posture

`[CRYPTO]` is **not** a FIPS 140 validated module and makes no HIPAA or
government certification claim (`docs/crypto-compliance-readiness.md`).
What it does provide as *compliance readiness controls*:

- keys generated through the component stay in kernel memory and are
  wiped when the descriptor session is released;
- descriptors bound operations, support irreversible attenuation,
  revocation, and optional expiry, and can be passed without exposing
  the secret;
- child keys come only from HKDF-SHA-256/512, returned as descriptors;
- `CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY` restricts issuance to
  AES-CBC, AES-GCM, and HMAC-SHA-256/384/512, rejecting ChaCha,
  XChaCha, AES-XTS, compression, and asymmetric descriptors — an
  algorithm-selection guardrail, not a validated mode.

FIPS validation would additionally require a defined module boundary,
self-tests, an approved entropy story, and CMVP laboratory testing; a
deployment must also verify that the OpenCrypto provider actually
selected lies inside a validated boundary — the hardware-class selector
alone is not evidence.

## Testing

`tests/sys/opencrypto/cryptodesc_test.c` covers mint validation,
metadata, generated keys and expiry, an RFC 5869 derivation vector,
X25519 exchange, Ed25519 sign/verify, concurrent use, cipher/digest/
EtA/AEAD operations, integrity failure, rights denial, and SCM_RIGHTS
transfer after the original descriptor closes.
`usr.sbin/localcrypto/tests` adds the provider policy matrix,
asymmetric-policy and driver-selection checks, and capability-bundle
security-contract tests.
`lib/libcryptocmp/tests` uses a fake service to exercise every operation and
status path plus short replies, bad magic/version/opcode/status, unexpected or
missing descriptors, output initialization, descriptor cleanup, and rejection
of a fork-inherited client. Named-key tests cover privilege captured at open,
owner isolation, duplicate names, lease rights, rotate/delete invalidation,
global and per-owner quotas, full-secret derivation, parent-right and TTL
ceilings, lineage revocation, concurrent operation, kqueue state, SCM_RIGHTS,
and teardown. The complete kernel, library, provider, EnvFD, BSDNotify,
filesystem-flavor, and TrustedZFS matrix runs in the disposable matching-kernel
guest provided by `tools/test/capability-qemu/`.
