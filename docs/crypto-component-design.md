# [CRYPTO] capability component

`[CRYPTO]` is the capability-bundle front end for OpenCrypto.  A service links
`libcryptocmp`, which connects to `system.Crypto` lazily on first use over
`service_connect(3)` and obtains descriptor-bound sessions from the provider.
The provider returns a `DTYPE_CRYPTO` attachment, never raw key material.

The kernel descriptor is intentionally independent of the provider.  Its
session algorithms and `CRYPTODESC_RIGHT_*` operation mask are immutable,
the descriptor is SCM-rights passable, and its final close tears down the
OpenCrypto session and clears retained key copies.  `/dev/crypto` remains the
compatibility control interface; `CIOCGCRYPTODESC` is its compatibility mint
operation while `CIOCGCRYPTODESCGENERATE` creates key material wholly inside
the kernel.

`localcrypto` owns the `/dev/crypto` control descriptor and asks the kernel to
generate separate cipher and MAC keys before minting the requested
rights-limited descriptor.  The worker never holds those key bytes.  It also
mints typed X25519 and Ed25519 descriptors.  `libcryptocmp` is the consumer
library for opening the local component and requesting a generated descriptor
or asymmetric key descriptor.  No application receives the `/dev/crypto`
control descriptor.

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

Callers handling a regulated workload may set
`CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY`.  This deliberately narrow profile
accepts AES-CBC, AES-GCM, and HMAC-SHA-256/384/512 and rejects ChaCha,
XChaCha, AES-XTS, compression, and asymmetric descriptors.  It is an
algorithm-selection guardrail, **not** a FIPS 140 validated mode or a claim
that a selected OpenCrypto provider is validated.  The compliance deployment
requirements and remaining certification evidence are documented in
[`crypto-compliance-readiness.md`](crypto-compliance-readiness.md).

The descriptor also supports monotonic authority reduction through
`CIOCSCRYPTODESCRIGHTS`.  A receiver may remove operation rights before
passing the descriptor on, but can never restore them.  This folds KeyVault's
useful capability-attenuation property into `DTYPE_CRYPTO`, rather than adding
a separate key-device capability surface.  `CIOCCRYPTODESCREVOKE` permanently
disables a descriptor before final close; subsequent operations fail with
`EACCES`.

Every component request is also recorded through the standard `Audit.cap`
capability using `libauditcmp`.  The record identifies the serviced client
label, operation, and result but contains neither key material nor descriptor
contents.  Audit-broker failure is non-authoritative: it cannot turn a denied
request into an allowed one or broaden an issued descriptor.

Generated and derived descriptors can have a bounded lifetime; once their TTL
has elapsed, every operation fails with `ESTALE`.  `CIOCCRYPTODESCDERIVE`
implements RFC 5869 HKDF-SHA-256/512 and produces another opaque descriptor,
never derived bytes.  X25519 descriptors permit only `EXCHANGE`; Ed25519
descriptors permit independently attenuable `SIGN` and `VERIFY` operations.

`[CRYPTO]` can also own a named volatile symmetric key object.  Names are
bound to the serviced client label, are not a global cross-service namespace,
and never reveal key bytes.  A create records the approved session profile and
maximum rights; a lease can only request a subset and produces an ordinary
short-lived descriptor.  Rotation changes the object generation and causes
older leases to fail with `EACCES`; deletion has the same effect and removes
the name.  These objects do not survive a module unload or reboot.

The regression suite in `tests/sys/opencrypto/cryptodesc_test.c` covers mint
validation, descriptor metadata, kernel-generated keys and expiry, an RFC 5869
derivation vector, X25519 exchange, Ed25519 signing/verification, concurrent
descriptor use, cipher, digest, encrypt-then-authenticate, and AEAD operations,
integrity failure, rights denial, and SCM_RIGHTS transfer after the original
descriptor is closed.  `usr.sbin/localcrypto/tests` adds the provider policy
matrix, asymmetric-policy checks, driver-selection checks, and
capability-bundle verification/security-contract tests.

## Deliberate extension boundaries

Current descriptors contain kernel-generated session-scoped symmetric or
asymmetric material, plus the volatile named symmetric-key objects described
above.  Persistent key lifecycle work is specified in
[`crypto-keyvault-integration.md`](crypto-keyvault-integration.md).  It folds
the safe KeyVault patterns into `[CRYPTO]` and `DTYPE_CRYPTO`; it does not add
KeyVault as a second device, daemon, or key authority.  `[CRYPTO]` must never
persist plaintext keys outside the kernel boundary.
Certificate parsing, RSA/ECDSA, and trust validation remain separately
specified in [`crypto-asymmetric-design.md`](crypto-asymmetric-design.md).
