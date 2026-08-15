# [CRYPTO] and KeyVault integration

## Status

`[CRYPTO]` is the only component and `DTYPE_CRYPTO` is the only descriptor
surface.  There is no KeyVault provider, client library, bundle, daemon, or
`/dev/keyvault` device in this tree.  `[CRYPTO]` creates session-scoped random
symmetric, X25519, and Ed25519 keys in the kernel and returns only
`DTYPE_CRYPTO` descriptors; it does not yet implement named or persistent
keys.  A file, database, or
UCL-backed store in a separate KeyVault service would create a second key
authority and expose recoverable plaintext key material outside the kernel
boundary.

The upstream KeyVault reference (revision `172e3d6`) was evaluated as a source
of implementation patterns.  Its useful per-file capability attenuation and
revocation semantics are now implemented directly by `DTYPE_CRYPTO` through
`CIOCSCRYPTODESCRIGHTS` and `CIOCCRYPTODESCREVOKE`; its HKDF, expiry, X25519,
and Ed25519 primitives have been reworked under the same descriptor ABI.  Its standalone module
must not be imported: it has a separate device ABI, repeats OpenCrypto session
ownership, and failed runtime evaluation in this environment.  The remaining
remaining useful primitives (named kernel key objects and auditing) must be
reworked as `[CRYPTO]` extensions, not copied as a parallel authority.

## Required `[CRYPTO]` key-lifecycle contract

The eventual `[CRYPTO]` key-lifecycle extension is the sole owner of key
naming, persistence, import, export policy, rotation, deletion, and audit
identity.  The descriptor's existing per-file capability mask is the basis for
a lease.  The component interface must:

1. create or import a named key under a declared algorithm and usage policy;
2. retain an opaque key reference, never plaintext key bytes, in `[CRYPTO]`;
3. mint a short-lived, rights-reduced `DTYPE_CRYPTO` lease;
4. revoke leases on expiry, rotation, or deletion; and
5. produce an audit event for create, import, lease, use, rotate, revoke, and
   delete operations.

The opaque reference must be bound to the `[CRYPTO]` authority, key version,
algorithm/profile, caller service identity, requested `CRYPTODESC_RIGHT_*`
mask, and expiry.  `[CRYPTO]` verifies those attributes before minting a
kernel descriptor.  It may receive an already-minted kernel key object or
perform a kernel-mediated unwrap, but persistent key bytes must never cross a
component channel.

## Descriptor flow

```text
consumer -- named-key request --> [CRYPTO] -- policy/key lookup --> kernel key object
consumer <-- DTYPE_CRYPTO fd ---- [CRYPTO] <-- scoped lease ----- kernel key object
                                      |
                                      +-- OpenCrypto session --> OpenCrypto
```

The returned descriptor remains passable by `SCM_RIGHTS`, but its rights are
intersected with both the lease and `[CRYPTO]` profile policy and can only be
reduced.  Closing the last descriptor reference destroys the OpenCrypto
session; revocation blocks future use.  Once kernel key-object support exists,
rotation and deletion must invalidate outstanding leases according to the
`[CRYPTO]` policy.

## Implementation prerequisites

Before named-key code is added, `[CRYPTO]` needs a kernel-safe opaque key-object
path.  Tests must cover lease isolation between services, authorization
failures, rotation/revocation, audit records, restart recovery, and proof that
plaintext persistent key bytes cannot be observed in the `[CRYPTO]` worker or
consumer process.
