# [CRYPTO] capability component

`[CRYPTO]` is the capability-bundle front end for OpenCrypto.  A service
declares `components = ["crypto"]`; serviced creates one private local
component session, and `libcryptocmp` obtains descriptor-bound sessions from
the provider.  The provider returns a `DTYPE_CRYPTO` attachment, never raw
key material.

The kernel descriptor is intentionally independent of the provider.  Its
session algorithms and `CRYPTODESC_RIGHT_*` operation mask are immutable,
the descriptor is SCM-rights passable, and its final close tears down the
OpenCrypto session and clears retained key copies.  `/dev/crypto` remains the
compatibility control interface; `CIOCGCRYPTODESC` is its mint operation.

`localcrypto` owns the `/dev/crypto` control descriptor, generates separate
cipher and MAC keys, mints the requested rights-limited descriptor, and
returns it over the typed channel protocol.  Its worker enters capability
mode before serving consumers.  `libcryptocmp` is the consumer library for
opening the local component and requesting a generated descriptor.  No
application receives the `/dev/crypto` control descriptor.

The regression suite in `tests/sys/opencrypto/cryptodesc_test.c` covers mint
validation, descriptor metadata, cipher, digest, encrypt-then-authenticate,
and AEAD operations, integrity failure, rights denial, and SCM_RIGHTS
transfer after the original descriptor is closed.
