# [CRYPTO] and KeyVault integration

## Status

`[CRYPTO]` is the only component and `DTYPE_CRYPTO` is the only descriptor
surface.  There is no KeyVault provider, client library, bundle, daemon, or
`/dev/keyvault` device in this tree.  `[CRYPTO]` creates session-scoped random
symmetric, X25519, and Ed25519 keys in the kernel and returns only
`DTYPE_CRYPTO` descriptors.  It also implements named, **volatile** symmetric
key objects owned by the kernel and scoped to the serviced client label.
`[CRYPTO]` can create, lease, rotate, and delete those objects without exposing
their bytes.  They are deliberately not persistent: module unload destroys
them.  A file, database, or UCL-backed store in a separate KeyVault service
would create a second key authority and expose recoverable plaintext key
material outside the kernel boundary.

The upstream KeyVault reference (revision `172e3d6`) was evaluated as a source
of implementation patterns.  Its useful per-file capability attenuation and
revocation semantics are now implemented directly by `DTYPE_CRYPTO` through
`CIOCSCRYPTODESCRIGHTS` and `CIOCCRYPTODESCREVOKE`; its HKDF, expiry, X25519,
and Ed25519 primitives have been reworked under the same descriptor ABI.  Its standalone module
must not be imported: it has a separate device ABI, repeats OpenCrypto session
ownership, and failed runtime evaluation in this environment.  The remaining
useful primitive, auditing, must be reworked as a `[CRYPTO]`
extension, not copied as a parallel authority.

## Required `[CRYPTO]` key-lifecycle contract

`[CRYPTO]` is the sole owner of the current volatile-key naming, rotation,
deletion, and lease identity.  The descriptor's existing per-file capability
mask is the basis for a lease.  The implemented interface can:

1. create a kernel-generated named key under a declared algorithm and usage policy;
2. retain an opaque key reference, never plaintext key bytes, in `[CRYPTO]`;
3. mint a short-lived, rights-reduced `DTYPE_CRYPTO` lease;
4. revoke leases on expiry, rotation, or deletion; and
5. bind every name to the serviced client label so another service cannot
   operate on it.

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
session; revocation blocks future use.  Rotation and deletion invalidate
outstanding leases by changing the key-object generation; the next use fails
with `EACCES`.

## Remaining lifecycle work

The current implementation intentionally has no import, export, persistence,
restart recovery, or audit-log ABI.  Any future persistence design must keep
plaintext keys outside neither the component worker nor the consumer process;
it needs a separately reviewed kernel-mediated wrapping boundary.  Future
tests must cover component-to-component isolation, audit records, restart
recovery, and proof that persistent plaintext key bytes are never observable.
