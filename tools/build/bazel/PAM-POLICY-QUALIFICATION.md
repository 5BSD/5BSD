# PAM policy installation qualification (2026-11-02)

## Native ownership

`//lib/libpam/pam.d:install_manifest` and `:install_archive` own the original
policy files and their Make installation metadata. No policy payload is changed.
The existing three explicitly exported fixture inputs retain their visibility.
Original Make selection includes eleven core files and cron unconditionally,
atrun with MK_AT, and ftp/ftpd with MK_FTP. Package tags remain pam, cron and at,
including the config marker. README is 0444; other files are 0644, root:wheel.
The explicit `/etc/pam.d` directory is 0755, root:wheel, package utilities.

The existing typed `//tools/build/bazel/config:at` and new typed `:ftp` booleans
both default true. Normal format-5 build-settings select both tested variants;
no frontend C, signing, stage or publication API changes are needed. Production
Bazel actions do not query Make. Make remains the production default.

## Evidence

All paths below are under `/usr/obj/usr/src/`.

- `bazel-pam-policy-default-native-qualification-r3-20261102` and
  `bazel-pam-policy-reduced-native-qualification-r2-20261102` passed through the
  maintained build-bsd frontend, compact execution logging, 16 jobs and the
  recorded 18 GiB start/16 GiB free-space guard. These are metadata/archive
  builds, not runtime tests or measured build-performance comparisons.
- `bazel-pam-policy-{default,reduced}-make-r3-20261102` independently builds and
  stages the original Make leaf in ordinary reference mode. Both receipts pass
  their selected profile, source-file-set and input-content checks. Reduced
  explicitly disables AT and FTP. No host configuration is installed.
- `bazel-pam-policy-install-audit-r2-20261102/report.json` verifies each immutable
  native archive/request binding and rechecks Make source snapshots. Default
  fifteen and reduced twelve file payloads equal the source and Make-installed
  bytes exactly. All 29 unique file/directory records match types, ownership,
  modes and package/config tags. Each Make METALOG emits the same directory
  twice: both original lines are retained, and only that exact duplicate is
  collapsed for comparison. No differing or file duplicate is accepted.

The first metadata-mode Make attempt failed its source-file-set guard after
creating fifteen source-directory recipe logs in this NO_OBJ leaf. They were
hash-preserved and removed by exact identity; original files are unchanged.
The separately committed NO_OBJ/NOOBJ preflight and ten native regression
methods are documented in MAKE-REFERENCE-METADATA-QUALIFICATION.md. Original
failed receipts, initial archive comparisons without the explicit directory,
and all subsequent controls remain retained.

## Limits and next gates

This qualifies the selected component archive/request and preserved policy
payloads. It does not exercise authentication, login, SSH, policy evaluation,
installation on the host, other configurations/architectures, whole PAM/world
composition or final pkg creation. The archive/request contains the explicit
utilities directory; the existing optional directory_metadata output is empty
when directory_packages is not selected. A future package composer must consume
and reconcile that explicit record rather than infer directory ownership from
file tags. Broad selection of utilities mtree directories would incorrectly add
unrelated component paths and is not used here. No compiled probes or audit
hooks are added or removed by this data-only installation declaration.
