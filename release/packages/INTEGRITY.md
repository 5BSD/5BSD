# Optional keyless pkgbase integrity check

This is an offline development check, not a signature, veriexec enforcement,
authenticated boot, or a root-resistant seal. It needs no signing key.

After installing pkgbase and completing configuration/migrations in a
quiescent candidate root:

    sh /usr/src/release/packages/base-integrity.sh create /path/to/candidate /path/to/candidate.mtree
    sh /usr/src/release/packages/base-integrity.sh check /path/to/candidate /path/to/candidate.mtree

Keep the manifest outside the candidate. Creation refuses to overwrite an
existing manifest. Checking reports extra, missing, changed, and metadata-
mismatched entries, returns nonzero on differences, and never repairs them.

The entire supplied tree is covered, including configuration. Supply only the
base generation; do not mount shared home, var, tmp, or third-party datasets
inside it. The helper rejects the active root path `/`, but does not freeze
writers or create snapshots.

The baseline records actual filesystem ownership, not NO_ROOT staging METALOG
ownership. An unprivileged staging baseline verifies that staging tree, not
the ownership of a deployed installation. Generate deployment baselines after
metadata has been applied.

Create a separate manifest per update candidate and verify before activation.
An attacker who can replace both files and baseline can evade this check.
Authenticated releases must compare against trusted signed release metadata,
not accept whatever an installation script produced.

## Opt-in veriexec export and signed loading

The mtree baseline is not a veriexec manifest. To generate the separate
veriexec input after installing/configuring a pkgbase candidate:

    sh /usr/src/release/packages/base-integrity.sh veriexec /path/to/candidate /path/to/base.veriexec

This emits relative paths, SHA-256 fingerprints and executable modes for every
regular file in the supplied tree, without requiring a key. It refuses an empty
tree, existing output, output inside the candidate, and pathnames the veriexec
lexer cannot safely represent. Symlinks are not followed or fingerprinted:
their regular-file targets must be covered independently, and the mtree check
remains necessary for link topology, ownership, missing and extra files.
Generation reads actual staging modes, not METALOG; apply deployment metadata
first. Keep the candidate quiescent throughout generation and signing.

Build the userland loader and its libraries with WITH_BEARSSL=yes and
WITH_VERIEXEC=yes in the world/pkgbase build. The kernel also needs MAC_VERIEXEC
and the SHA256 fingerprint backend. These instructions do not change build or
boot defaults. Test programs remain in the tests package.

The existing /sbin/veriexec loader requires a detached signature recognized by
libsecureboot and a matching trusted signer configured in the target build.
A locally generated manifest is NOT publisher-authenticated. Users without a
trusted signing setup can use the keyless mtree check and export, but cannot
load this manifest through the signed loader. No unsigned bypass is added.

After signing with that release/development trust setup, an authorized operator
can explicitly load the candidate's fingerprints and check a covered path:

    veriexec -S -C /path/to/candidate /path/to/base.veriexec
    veriexec -x /path/to/candidate/bin/sh

The first command changes the running kernel's fingerprint table, even with -C;
it is not an offline-only operation. Use a disposable VM for qualification.
Loading can partially succeed before an error; a nonzero status must stop the
workflow. Loading does not itself enable or lock enforcement.

For updates, finish installation and migrations before generating a new manifest.
Verify/sign that candidate, then load its manifest again at boot on the actual
selected filesystem. Do not assume fingerprints loaded for a staging tree or
another boot environment apply to a newly installed copy. Do not run this as an
unconditional pkg post-install hook: hashing the current files alone would bless
whatever bytes happen to be present, and loading/enforcement affects the host.

Automatic boot loading, enforcement/locking, authenticated boot and protected
mounts remain separate work. Do not enable enforcement until executable,
interpreter and library coverage is tested, including the intended policy for
unsigned /usr/local software. Exporting a base manifest alone does not establish
that policy or a sealed system.
