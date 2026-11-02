# Independent Make recipe metadata qualification

## Implemented scope

`install-reference.py --make-meta` records supported Make metadata from the
initial build, using the single argument
`.MAKE.MODE=meta missing-meta=yes nofilemon curdirok=yes`. It remains disabled
by default. The receipt records the selected mode and complete commands.
This supports auditing original compile recipes when subsequent DTrace actions
transform the object: rebuilding an individual object to recover its recipe
would change the reference being examined.

The switch accepts no mode value or arbitrary Make assignments. Existing source,
SDK, profile, path and restricted component-option validation remains in force.
This is an independent qualification oracle; production Bazel actions do not
interpret Make metadata. Normal build-bsd format-5 target/test inputs need no new
C frontend or SDK interface.

## Performed checks (2026-11-02)

- The normal maintained frontend ran
  `//tools/build/bazel:install_reference_options_test` with all seven actual
  unittest methods passing. Three attempted values for `--make-meta=...` are
  rejected by the actual CLI before filesystem/build work.
- The existing six installation-reference guard tests passed.
- A fresh APM reference with the default mode built and installed successfully.
- A fresh pam_deny reference with metadata enabled built and installed
  successfully. Original static/PIC compiler recipes and DTrace/provider/archive
  metadata were retained and checked against their object directories and sources.

Evidence under `/usr/obj/usr/src/`:

- `bazel-static-pam-helper-test-qualification-r1-20261102`
- `bazel-static-pam-reference-guards-r1-20261102`
- `bazel-static-pam-reference-control-default-apm-r1-20261102`
- `bazel-static-pam-reference-control-metadata-pam-deny-r1-20261102`
- `bazel-static-pam-reference-control-r1-20261102.json`

The last summary has an observer-only label error: its metadata result's `name`
is `pam_deny.pico`, from a loop variable shadowing the job label. Its explicit
command, output path, selected mode and successful underlying helper receipt
identify the intended pam_deny control. The original summary is retained.

These checks do not qualify the native static PAM archive, authentication,
installed default paths, a complete system build or performance.


## NO_OBJ directory preflight (2026-11-02)

Explicit --make-meta now rejects components defining NO_OBJ or legacy NOOBJ
before output creation or build/install actions. Make uses definedness here:
empty values and even a literal no still suppress the object directory. Ambiguous
query output fails closed. Ordinary reference mode keeps its existing behavior.

The original pam.d attempt exposed this source-write hazard: 15 untracked install
recipe .meta files were generated in the NO_OBJ source directory. Both original
helper receipts correctly failed their source-file-set guard. Exact files/hashes
were preserved before removing only those generated files; all original policy
and source bytes were rechecked against both initial snapshots.

Evidence under /usr/obj/usr/src/:

- bazel-pam-policy-source-metadata-preservation-r1-20261102 records all 15 copies,
  their absent-before identity and bounded cleanup.
- bazel-pam-policy-noobj-metadata-rejection-r1-20261102 proves the actual maintained
  leaf rejects --make-meta before creating the requested output or changing source.
- bazel-pam-policy-default-native-qualification-r2-20261102 runs the declared native
  bmake regression through the normal frontend: ten actual unittest methods pass
  (one Bazel XML wrapper case), including real Make definedness and non-executed
  recipe controls. No host Make fallback is allowed within Bazel.
- bazel-pam-policy-make-references-r2-20261102.json records two fresh successful
  ordinary-mode Make install controls after the preflight fix. These are reference
  controls; separate policy payload/installation qualification is required.

No arbitrary Make-variable interface is added. Production Bazel actions, SDK/profile
checks and the default-off metadata setting retain their existing behavior.
