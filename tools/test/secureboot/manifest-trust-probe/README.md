# Native manifest trust qualification

This probe compiles the actual loader trust initialization, certificate parser,
and BearSSL verification sources as a native program. The verification-required state now comes from the actual verify_file code.
EFI variable reads and panic transport are native seams. It does not
exercise firmware, PE verification, loader startup, generation authorization or
rollback protection. Do not use it as a release gate substitute for those tests.

`manifest-trust-prepare` in the parent Makefile requires a new `TRUST_WORK`
directory. It creates four disposable RSA signing identities (firmware, generation, application and repository), keeps their private
keys there with mode 0600 inside mode 0700 directories, and calls the maintained
boot-manifest signing backend. Never package this work directory or enroll its
keys. It is a test fixture, not a production trust store.

Build two copies of this directory with the matching `/usr/src` buildenv, all
logical CPUs, and separate fresh MAKEOBJDIR directories under `/usr/obj`:

- Firmware probe: `WITH_LOADER_EFI_TRUST_DB=yes`, no compiled anchors.
- Compiled probe: `WITHOUT_LOADER_EFI_TRUST_DB=yes` and
  `TRUST_ANCHORS=${TRUST_WORK}/generation/public.crt`.

Pass `SRCCONF=/dev/null __MAKE_CONF=/dev/null` to both test builds so unrelated
host policy cannot choose the fixture's trust anchors. These are native test
builds only; they do not install or build an EFI image. The Makefile retains the
standard BearSSL per-source compiler-warning exceptions from its library build.

Run the parent target `manifest-trust-crypto-test` with `TRUST_WORK`,
`FIRMWARE_TRUST_PROBE`, and `COMPILED_TRUST_PROBE` explicitly selected. The driver
requires the expected cryptographic rejection reason as well as exit status.
Its ten cases cover intended acceptance, rejection of firmware/application/repository
signers by a generation-only trust store, revocation,
tampered content, and empty/duplicate decoded signatures. `results.json` records scope, outcomes and public-artifact/probe
hashes. Repeated runs retain a separately named tampered fixture; they do not
modify the original signed inputs. No command here starts a VM.

Role names identify test inputs, not certificate attributes enforced by the loader.
Separation comes from the explicit compiled trust-anchor membership. Selecting an
application or repository key as a generation anchor would grant it that authority.

## Root-descriptor reader integration

The probe also compiles actual verify_file, veopen and verified_root sources.
`--root-descriptor path` exercises manifest lookup, signature verification, file
hashing and private-buffer verification through the real reader. Native stand.h
supplies host declarations; manifests.h deliberately searches only the fixture's
co-located manifest. Neither file replaces production loader policy.

Run parent target `root-descriptor-crypto-test` with explicit `TRUST_WORK`,
`COMPILED_TRUST_PROBE` and `TRUST_OPENSSL`. It signs structurally valid test root
descriptors using the maintained signing backend and the prepared disposable
identities. It checks generation acceptance, firmware/application/repository
rejection, revocation, changed file contents and correctly signed short/oversized
inputs. Every negative case requires its expected rejection reason. Results are
retained in a fresh root-reader-* directory beneath TRUST_WORK. This does not
mount the synthetic data image or qualify its filesystem, mandatory image
selection, kernel admission, firmware execution, updates or rollback protection.
