# Library fresh-account construction follow-up

## Result (2026-11-06)

The existing source-owned //etc:account_databases and
//etc:account_install_archive construct through build-bsd bazel-test with the
current AMD64 qualification inputs and all 16 CPUs. The source-settings wrapper
passes. No account generator implementation change was needed.

The archived /etc/passwd, /etc/pwd.db and /etc/spwd.db match the complete original
Make lib installconfig outputs byte-for-byte. The audit verifies the passed
original receipt and component.METALOG hash, records the actual installconfig log,
and resolves immutable native outputs through qualification_artifacts. Archive
members are regular files with numeric root/wheel ownership and modes 0644,
0644 and 0600, respectively. Their installation manifests carry no package tags.
Only the repository's public default account input was used. Raw Bazel/cache
artifacts are not a private credential store.

The existing generator uses its declared master.passwd and shells inputs with
the source-built execution-platform pwd_mkdb and -S shell-policy option. It does
not read host account files as its account source, install host files or modify
host authentication. Byte equivalence is established for this selected source
configuration, not every account or target-endian configuration.

## Construction versus packages

libc's config_archive already includes the account construction manifest, while
its complete install_archive deliberately excludes generated databases.
The world_contributions/finalized_world_contributions hierarchy currently selects
production library payloads and manual database finalization; it does not select
the separate account archive. This explains the three missing paths in the full
library payload comparison. That comparison remains differences-found; the new
account evidence must not be silently treated as if those paths were present.

The package contract packages/runtime/runtime.ucl declares account-database
construction outputs with replace=false and performs bootstrap/migration in
install scripts. The native package layout requires a package tag on payload
records. Untagged generated databases must remain separate construction state;
assigning them a runtime package tag would risk replacing local accounts and
would contradict the existing contract.

Next integrate complete fresh-system construction with explicit source account
inputs and nonreplacement checks, keeping package payloads distinct. Qualify the
same path during package-driven staging and upgrades, including existing accounts
and installed lookups/login/PAM/SSH. A tar and byte comparison alone do not prove
that migration or nonreplacement is enforced. Existing typed configuration and
execution-platform generator facilities must be used rather than copied host
files or one-off image helpers. The TCSH-disabled Make source transformation,
nondefault accounts/shells and cross-target behavior also need qualification.

## Evidence under /usr/obj/usr/src

- bazel-library-account-construction-request-r1-20261106/inputs.json.
- bazel-library-account-construction-native-r1-20261106: passed frontend run,
  immutable outputs and source-settings report.
- bazel-library-complete-make-r2-20261106: passed original full library control.
- bazel-library-account-construction-review-r2-20261106: passed bounded audit,
  retained script, hash bindings, modes and original/native file hashes.
- The earlier review-r1 is retained; r2 additionally verifies original receipt
  metadata and records installconfig provenance.

Frontend review: existing format-5 explicit targets qualify these candidates;
no new CLI/backend/signing/publication behavior was introduced in this follow-up.
The maintained manual records this evidence and staging limitation. No host
installation, publication, verified boot, root protection or reboot is claimed.
Make remains the production default; all broader completion gates remain open.
