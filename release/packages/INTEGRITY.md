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

Veriexec import/enforcement and protected-mount policy remain separate work.
This mtree format is not a veriexec manifest.
