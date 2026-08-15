# [CRYPTO] asymmetric and certificate extension

`DTYPE_CRYPTO` currently represents an OpenCrypto symmetric/compression
session.  It must not be widened into an untyped asymmetric-key or certificate
handle.  The asymmetric work is an extension of the `[CRYPTO]` component, with
its own versioned client library and a typed descriptor or kernel-key-object
ABI.  It is not a second capability component or a KeyVault service.

## Scope

The component owns policy-mediated access to:

* RSA-PSS and ECDSA/EdDSA signing and verification;
* X25519/ECDH key agreement;
* public-key import/export and certificate/chain parsing; and
* certificate-chain and trust-anchor validation.

Private key lifetime and named-key authority belong to the `[CRYPTO]`
key-lifecycle extension.  The asymmetric `[CRYPTO]` service obtains the same
opaque, scoped leases described in
[`crypto-keyvault-integration.md`](crypto-keyvault-integration.md), and only
returns a rights-limited operation descriptor to its caller.  Certificate and
public-key data may cross the component boundary; private key bytes may not.

## Required policy and tests

Each descriptor must bind algorithm, parameter size/curve, intended operation,
service identity, `[CRYPTO]` key version, and expiration.  Signing and key
agreement rights must be distinct.  Certificate validation must make hostname,
time source, EKU, path-building, revocation, and trust-anchor policy explicit.

Before implementation, add kernel and component tests for known-answer
vectors, invalid signatures, malformed DER, chain/path failures, unsupported
curves and sizes, rights denial, cross-service lease isolation, descriptor
passing, concurrency, key rotation/revocation, and audit completeness.
