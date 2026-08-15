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

## Provider policy

The provider is deliberately a policy boundary, not a generic raw `/dev/crypto`
proxy.  It accepts only the profiles implemented and tested in
`usr.sbin/localcrypto/policy.c`:

* AES-CBC with 128-, 192-, or 256-bit keys and a 16-byte IV;
* AES-GCM-16 with a 96-bit nonce and a 16-byte tag;
* ChaCha20-Poly1305 and XChaCha20-Poly1305 with their standard 96- and
  192-bit nonces and 16-byte tags;
* AES-XTS with 256- or 512-bit combined keys and a 16-byte tweak;
* HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512; and
* DEFLATE compression.

Requests have a 64-byte cipher-key and MAC-key ceiling.  A request may select
the default driver, software, or hardware OpenCrypto class, but cannot name an
arbitrary driver ID.  Encrypt/authenticate and decrypt/verify rights are paired
for authenticated profiles, preventing an accidental encrypt-without-tag or
decrypt-without-verification descriptor.  Unsupported primitives fail with
`EPROTONOSUPPORT`; malformed profiles fail with `EINVAL`.

The descriptor also supports monotonic authority reduction through
`CIOCSCRYPTODESCRIGHTS`.  A receiver may remove operation rights before
passing the descriptor on, but can never restore them.  This folds KeyVault's
useful capability-attenuation property into `DTYPE_CRYPTO`, rather than adding
a separate key-device capability surface.  `CIOCCRYPTODESCREVOKE` permanently
disables a descriptor before final close; subsequent operations fail with
`EACCES`.

The regression suite in `tests/sys/opencrypto/cryptodesc_test.c` covers mint
validation, descriptor metadata, cipher, digest, encrypt-then-authenticate,
and AEAD operations, integrity failure, rights denial, and SCM_RIGHTS transfer
after the original descriptor is closed.  `usr.sbin/localcrypto/tests` adds
the provider policy matrix, driver-selection checks, and capability-bundle
verification/security-contract tests.

## Deliberate extension boundaries

Current descriptors contain newly generated, session-scoped symmetric material.
They are not named or persistent.  The next key-lifecycle work is specified in
[`crypto-keyvault-integration.md`](crypto-keyvault-integration.md).  It folds
the safe KeyVault patterns into `[CRYPTO]` and `DTYPE_CRYPTO`; it does not add
KeyVault as a second device, daemon, or key authority.  `[CRYPTO]` must never
persist plaintext keys outside the kernel boundary.
Asymmetric keys, certificate parsing, signing, verification, and key agreement
are specified separately in
[`crypto-asymmetric-design.md`](crypto-asymmetric-design.md), rather than
overloading the symmetric `DTYPE_CRYPTO` ABI.
