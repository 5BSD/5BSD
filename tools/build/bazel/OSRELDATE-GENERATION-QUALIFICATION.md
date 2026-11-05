# Declared-input osreldate generation qualification

## Maintained generator interfaces (2026-11-05)

The native `//include:osreldate` action produces the public OS version header from
five declared files: mk-osreldate.sh, newvers.sh, sys/param.h, COPYRIGHT and the
maintained copyright template. Its execution tools are declared SDK sh/awk/sed
and the existing stdout redirect helper. Tool aliases give subprocesses a bounded
PATH. Starlark defines the action and installation; maintained shell scripts
produce the bytes. No Python construction implementation or Make invocation is
introduced.

newvers.sh adds -C, an explicit copyright-only query requiring the source
COPYRIGHT and template. It neither reads param.h nor discovers source/clock
metadata. Exact -v/-V RELDATE queries can use PARAMFILE without discovering a
source directory or rendering copyright. Existing -c and explicit kernel -e
interfaces remain available.

mk-osreldate.sh adds -s: stateless stdout with explicit NEWVERS_SH, PARAMFILE,
NEWVERS_COPYRIGHT and NEWVERS_COPYRIGHT_TEMPLATE inputs. It emits no banner or
temporary files in this mode and validates the numeric version without eval.
Default Make calls retain atomic file output and their existing bytes. The
public-header helper now accepts the root include directory while leaving that
common directory's policy with mtree. osreldate_install_archive installs one
root/wheel 0444 file with clibs/dev tags; it is not a complete include endpoint.

## Evidence

All evidence below is under `/usr/obj/usr/src/`.

- `bazel-osreldate-native-r2-20261105`: maintained build-bsd bazel-test, sixteen
  jobs. Source-settings and the new generation test target pass. The generation
  target runs three unittest methods covering normal/altered inputs, missing or
  invalid inputs, and minimum dependency queries. Its tools PATH contains only
  declared SDK sh/awk/sed. A future fixture uses its own version and copyright
  year; production version/year values are never pinned in the rule.
- `bazel-complete-include-make-r3-20261105`: fresh complete original Make include
  build/stage using the maintained generator's default file mode, sixteen jobs,
  unchanged selected SDK/profile, tests disabled. Its staged-object guard passes.
- `bazel-osreldate-original-review-r1-20261105/review.json`: exact header bytes,
  complete file metadata and tar attributes match the fresh original record and
  payload. Original source bindings, receipts, metadata and native artifacts are
  bound. All eighteen preceding fixed-header archive/metadata outputs remain
  byte-identical after the shared helper's root-directory support was added.
- `bazel-osreldate-version-regression-r1-20261105/review.json`: previous committed
  versus current newvers outputs match byte for byte for -c, -v, -V RELDATE and
  explicit kernel -e/vers.c. This uses explicit kernel fixture inputs and host
  shell/tools; it is interface regression evidence, not a kernel rebuild or a
  hermetic compiler-bootstrap result. The existing newvers-errors-test.py also
  passes its two tests, including failed metadata producers and explicit inputs.

The initial native run r1 completed the generators but failed a test because its
fixture source files were absent from runfiles. Those inputs were declared and r2
passes; r1 remains failed. Its actual completed production generator action log
is decoded with the bound upstream converter. All five source input digests match
current files, and its output digest matches the final passing r2 archive payload.
This is bounded producer provenance from the failed initial run, not acceptance
of that run as a successful qualification. The audit retains that distinction.
The observed runner is processwrapper-sandbox; complete OS isolation is not
established by this evidence.

`bazel-osreldate-namespace-r1-20261105/review.json` reconciles the new file with
preceding AMD64-selected production captures: 1169 unique archives and 30992
non-directory paths, zero conflicts. The separately requested ARM companion data
archive is excluded from AMD64 counts. This remains cross-capture namespace
evidence, not a combined world build or whole-world directory/pkgbase acceptance.

## Frontend and remaining gates

The maintained format-5 target/settings interface and archive output groups
already support the new contribution. Its manual documents declared-input version
generation. No C dispatcher/schema, signing/staging/publication helper change is
needed. The affected normal Make generator path was tested through the full
original include reference; no replacement build workflow was introduced.

Continue ordinary root, source kernel/architecture headers and aliases, then the
complete include parent and remaining etc/rescue/sys/stand/world/installed tests.
Complete installation/debug/pkgbase parity, other ABIs/configurations, reproducible
bootstrap/package inputs, runtime/VM and comparative CPU/memory/disk qualification
remain open. This does not establish a rebuilt kernel after the script change.
Runs are unsigned development qualification with no publication, host installation,
upgrade or reboot. Make stays production/default and available for ports; BIP is
excluded.
