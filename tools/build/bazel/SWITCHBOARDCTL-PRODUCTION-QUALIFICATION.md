# Switchboardctl native production candidate (2026-11-05)

## Later native construction checkpoint

The selected normal frontend batch and original comparisons now pass. See
[COMPOSITION-QUALIFICATION-20261105.md](COMPOSITION-QUALIFICATION-20261105.md)
for exact retained receipts, fixes and limits. The configured-only and prepared
request descriptions below record the earlier checkpoint. They do not describe
the current execution status. Runtime, alternate profiles and whole-system
qualification remain open.


## Implementation

The existing static test command objects remain unchanged. A separate native
rules_cc cc_binary compiles the six original C sources, with declared library
and private-header dependencies, PIE and the original default warning policy.
Its genuine compilation_outputs group is exposed for independent object review.
No Make command, SDK executable copy or generated replacement program is used.

The existing bsd_capimage_policy action embeds the original Unit.ucl bytes in
.5bsd.policy. The standard utility split-debug/strip actions preserve that
section. This is unsigned policy embedding; it is not signing, verified boot or
protection against compromised root. The existing stage/signing frontend remains
responsible for its separate validation and signing operations.

The complete production manifest includes the capability bundle/unit documents,
relative /usr/sbin command symlink, package-owned bundle/debug directories,
program, separate debug file and manual. Full tests-enabled installation rejects
selection until the original child test hierarchy is migrated; existing static
test targets are retained. AMD64 production is a candidate, not accepted runtime.

## Evidence and scope

All paths below are relative to /usr/obj/usr/src:

- bazel-switchboardctl-make-r1-20261105 passes the initial original reference.
- bazel-switchboardctl-make-r2-20261105 passes against the final candidate source
  file set, including the changed existing BUILD file and new production module.
  All source-set and compiler/SDK checks remain enabled.
- bazel-switchboardctl-analysis-r1-20261105/metadata-review/review.json binds the
  actual configured native dependency analysis and final original reference.
  All sixteen metadata records match types, destinations, owners, groups, modes,
  package/debug tags and the exact relative symlink target. Both original policy
  documents match installed source bytes. The program, debug file and compressed
  manual are explicitly pending native production.

The analysis builds no actions. It validates declared/configured dependencies
and complete installation metadata; it does not prove compilation, ELF library
order, retained embedded-policy bytes, debug CRC, archive headers or runtime.
Those comparisons remain required after the native build.

The expanded next normal frontend request is retained at
bazel-library-admin-composition-request-r2-20261105/request.json and inputs.json.
It supersedes the unstarted r1 request and selects the production archive, actual
program and actual source objects alongside the preceding library/script/test-root
batch. Neither request is queued: launch only after the current aggregate
frontend terminates. Existing format-5 dispatch accepts these labels; no C,
security-policy, staging/signing or publication interface change is required.
Make remains default. No host install, upgrade or reboot is authorized here.

## Other identified production gap

At this checkpoint usr.sbin/dtraced supplied native public/control headers only.
The subsequent [dtraced production candidate](DTRACED-PRODUCTION-QUALIFICATION.md)
now declares its eleven C++ sources, native dependencies and build-option graph.
Configured action/metadata checks pass; native compilation, diagnostic runtime
and cross-platform closure remain open. Header presence alone was not daemon
conversion, and the new declarations alone do not establish native acceptance.
