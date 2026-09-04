# Cryptographic Services

5BSD delivers cryptography to services as **capability descriptors, not key
bytes**. The `system.Crypto` capability service fronts the kernel OpenCrypto
framework: a service links `libcryptocmp`, connects to `system.Crypto` at
first use, and obtains descriptor-bound crypto sessions from the provider.
What comes back is a `DTYPE_CRYPTO` file descriptor — never raw key material,
and no plaintext key ever exists in userland.

## The service

The `localcrypto` provider (`usr.sbin/localcrypto/`) owns the `/dev/crypto`
control descriptor and asks the kernel to generate key material before minting
the requested rights-limited descriptor — neither the worker nor any
application ever holds key bytes or the control descriptor, which the provider
locks non-transferable with an exact ioctl allowlist before entering
capability mode. The provider is a deliberate policy boundary, not a raw
`/dev/crypto` proxy: it accepts a fixed set of symmetric profiles (AES-CBC,
AES-GCM, ChaCha20/XChaCha20-Poly1305, AES-XTS, HMAC-SHA-2, DEFLATE), pairs
encrypt/authenticate and decrypt/verify rights so an encrypt-without-tag
descriptor cannot be minted, and fails unsupported primitives closed.

Its operation set is deliberately small:

- **`GENERATE`** / **`GENERATE_KEY`** — mint session and key descriptors from
  kernel-generated material.
- **`NAMED_CREATE` / `NAMED_LEASE` / `NAMED_ROTATE` / `NAMED_DELETE`** —
  manage named volatile key objects (below).
- **`DIGEST`** — mint an ephemeral unkeyed-hash session descriptor
  (SHA2-256/384/512).
- **`RANDOM`** — bounded inline CSPRNG output, capped at 1024 bytes per
  request.

Every request is audited through the `system.Audit` capability (client label,
operation, result — no key material); audit failure is non-authoritative and
can never widen a grant.

## Descriptor semantics

A `DTYPE_CRYPTO` descriptor's algorithms and operation mask are immutable at
mint; it is passable over `SCM_RIGHTS`, and its final close tears down the
OpenCrypto session and clears retained key copies. Authority only shrinks:

- a holder can **drop** operation rights before passing a descriptor on, never
  restore them;
- a descriptor can be **revoked** permanently (`EACCES` thereafter) and may
  carry a **TTL** (`ESTALE` after expiry);
- **derivation** (RFC 5869 HKDF-SHA-256/512) returns another opaque
  descriptor, never derived bytes; a parent must hold both the derive right
  and every right requested for the child, the child TTL is clamped to the
  parent's, and a child of a named lease stays bound to the same generation so
  rotation revokes the entire derived lineage.

## Named keys

There is deliberately no separate KeyVault daemon or file-backed store — that
would put recoverable plaintext keys outside the kernel boundary. Instead the
kernel owns **named volatile symmetric key objects**: created under a declared
algorithm/usage policy, **owner-scoped by the requesting channel label** (no
global namespace), and leased as ordinary short-lived, rights-reduced
descriptors. Rotation bumps the object generation so older leases fail
`EACCES`; deletion does the same and removes the name. Objects do not survive
module unload or reboot, global and per-owner quotas bound the registry, and
there is intentionally no import, export, or persistence ABI — any future
persistence requires a separately reviewed kernel-mediated wrapping boundary.

## Asymmetric support

`localcrypto` mints typed X25519 (key exchange only) and Ed25519
(independently attenuable sign/verify) descriptors; broader asymmetric
support — RSA-PSS, ECDSA, certificate parsing, and trust-anchor validation —
is not provided. Every descriptor is typed and bound to algorithm,
operation, identity, key version, and expiry, and private key bytes never
cross the component boundary.

## Compliance posture

The service is **not** a FIPS 140 validated module and makes no certification
claim. As readiness controls: keys stay in kernel memory and are wiped on
release; descriptors bound operations and support irreversible attenuation,
revocation, and expiry; and a NIST-approved-only issuance flag restricts
profiles to AES-CBC, AES-GCM, and HMAC-SHA-2 — an algorithm-selection
guardrail, not a validated mode. FIPS validation would additionally require a
module boundary, self-tests, an approved entropy story, and CMVP testing.

Kernel, library, and provider behavior is exercised by ATF suites and the
disposable matching-kernel guest in `tools/test/capability-qemu/`.
