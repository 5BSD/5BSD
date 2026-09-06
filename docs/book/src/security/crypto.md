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

Two read-only introspection operations let a service inspect the named objects
it owns without minting or mutating anything. **`NAMED_STAT`** resolves one key
by name and returns its metadata — generation, granted-rights mask, cipher/MAC
selectors and key lengths — while delivering no descriptor and leaving the
generation untouched; a miss (or a key deleted under the owner) is `ENOENT`.
**`NAMED_LIST`** enumerates the owner's named keys, paginated through a resume
cursor, returning each key's name, generation and rights but never key
material. Both are owner-scoped on the hard invariant of every named-key
operation: the owner is the session's unforgeable channel label, never a wire
argument, so a caller can only ever observe keys minted under its own label.
The kernel keystore backs both with dedicated query and enumeration ioctls, so
introspection reads the authoritative object state rather than any userland
cache.

Limitations, honestly stated: asymmetric support is limited to X25519 key
exchange and Ed25519 signatures, and the service is **not** a FIPS 140
validated module — an approved-algorithms-only issuance mode is a selection
guardrail, not a certification claim.

Reference: `localcrypto(8)`.
