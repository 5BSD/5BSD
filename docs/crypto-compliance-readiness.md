# [CRYPTO] compliance readiness

`[CRYPTO]` is not currently a FIPS 140 validated cryptographic module, and it
does not make a HIPAA or government certification claim.  A source change or a
successful test suite cannot create that validation status.

## Controls implemented in this component

* Key material generated through `[CRYPTO]` remains in kernel memory and is
  wiped when the descriptor session is released.
* A descriptor limits operations, supports irreversible attenuation and
  revocation, has optional expiry, and can be passed without exposing its
  secret.
* Child keys use HKDF-SHA-256 or HKDF-SHA-512 and are returned only as another
  descriptor.
* `CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY` restricts component-issued
  symmetric descriptors to AES-CBC, AES-GCM, and HMAC-SHA-256/384/512.
  It rejects algorithms that are outside this profile.
* The regression suite exercises approved-profile admission and rejection,
  descriptor rights, expiry, derivation, and cryptographic operation paths.

## What remains outside the source tree

FIPS 140 validation requires a defined cryptographic boundary, approved mode
rules, startup/conditional self-tests, integrity controls, an approved entropy
story, configuration management, a security policy, and testing by an
accredited laboratory under the CMVP process.  A deployment must also ensure
that the actual provider selected by OpenCrypto is within the validated module
boundary; a hardware selector alone is not evidence of validation.

For HIPAA-regulated data, the organization must complete its risk analysis,
access control, audit, transmission, backup, incident-response, and vendor
management obligations.  `[CRYPTO]` helps keep keys scoped to descriptors but
does not replace those administrative and operational safeguards.

Before a compliance claim, produce a versioned security policy and module
boundary, pin and evidence the selected provider, add the required integrity
and power-up/conditional self-tests to that boundary, collect audit evidence
through the operating system's audit configuration, and complete the relevant
independent assessment.  Until then, describe this work as *compliance
readiness controls*, never as FIPS validated or HIPAA certified.
