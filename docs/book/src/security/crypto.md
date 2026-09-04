# Cryptographic Services

5BSD delivers cryptography to services as **capability descriptors, not key
bytes**. The `localcrypto` provider publishes the `system.Crypto` capability
in front of the kernel OpenCrypto framework: a service connects at first use
and obtains descriptor-bound crypto sessions. What comes back is a
`DTYPE_CRYPTO` file descriptor — never raw key material, and no plaintext key
ever exists in userland. The provider is a deliberate policy boundary, not a
raw `/dev/crypto` proxy: it accepts a fixed set of vetted symmetric and
hashing profiles, pairs encrypt/authenticate rights so a misleading
descriptor cannot be minted, and fails unsupported primitives closed. Every
request is audited through `system.Audit` (metadata only), and an audit
failure can never widen a grant.

A descriptor's algorithms and operation mask are immutable at mint, and
authority only shrinks: a holder can drop rights before passing a descriptor
on but never restore them, a descriptor can be revoked or carry an expiry,
and key derivation returns another opaque descriptor — never derived bytes —
whose authority and lifetime are clamped to its parent's.

There is deliberately no separate key-vault daemon or file-backed store —
that would put recoverable plaintext keys outside the kernel boundary.
Instead the kernel owns **named volatile key objects**, scoped to the owning
channel label and leased as short-lived, rights-reduced descriptors; rotating
or deleting an object invalidates every outstanding lease and its derived
lineage. Objects do not survive reboot, and there is intentionally no import,
export, or persistence ABI.

Limitations, honestly stated: asymmetric support is limited to X25519 key
exchange and Ed25519 signatures, and the service is **not** a FIPS 140
validated module — an approved-algorithms-only issuance mode is a selection
guardrail, not a certification claim.

Reference: `localcrypto(8)`.
