# Native libutil original tests — AMD64 qualification

## Integration

All twelve original programs now use native ATF/util/C ABI interfaces and native
C/sys runfiles. The source-owned program inventory retains original GNU17/WARNS=2,
PIE, extra production sources, private header inputs and linker wrappers.
login_time_error_test still compiles login_ok.c/login_times.c and wraps both time
conversion interfaces. login_cap_list_test still compiles login_cap.c/getcap.c
and wraps cgetstr/free/realloc/reallocarray. Original test and production sources
are unchanged. The original forkpty unprivileged requirement is preserved.

Each original program compiles through an owned alwayslink object group, retaining
Make's direct-source inclusion semantics. Normal and private-runtime links use
the same compiled input. Native cc_binary owns final links; normal installed
programs have no RPATH. Six TAP runtime-only variants add inherited private RPATH
for their isolated native loader checks. The test directory now has a complete
standalone installation archive. Its library parent already consumes the original
test manifests conditionally; that selection and complete payload remain.

Existing format-5 build-bsd inputs express the targets/options. No C frontend,
schema, signing or publication change is needed; the manual is updated in this
change. SDK headers/startup objects and the SDK Kyua controller remain bootstrap
inputs. Make remains default, the wider tests-enabled lib parent guard remains,
and BIP remains excluded. Extra historical static-consumer/fault-injection
qualification targets remain separate from this original installed-suite claim.

## Evidence

All paths below are under `/usr/obj/usr/src`. Native requests use build-bsd
bazel-test with `--arch amd64 --jobs 16`, explicit SDK/receipt/repository inputs,
TESTS_SUPPORT=yes, NIS disabled and MALLOC_PRODUCTION=yes. These are unsigned
qualification builds, not package publication, verified boot or host installation.

- `bazel-util-tests-make-r1-20261106`, `bazel-util-parent-make-r1-20261106` and
  `bazel-util-parent-no-tests-make-r1-20261106`: complete independent Make test
  and parent build/staging controls for both option profiles.
- `bazel-util-tests-request-r1-20261106/inputs.json` and
  `bazel-util-tests-native-r1-20261106`: complete native suite, parent,
  original twenty ATF cases, six TAP programs and separate source helper.
- `bazel-util-tests-review-r1-20261106/review.json`: all 25 test file records,
  five directory package claims, exact Kyuafile, twelve program ELF/debug
  contracts and all twenty actual ATF metadata records match Make. Original
  user metadata is preserved. Final immutable reports have 27 program/case-level
  passes: twenty ATF bodies, six TAP programs and one source helper. Nested
  TAP assertions/skips are accounted separately below.
- `bazel-util-parent-review-r1-20261106/review.json`: all 148 positive parent
  file/link records, six directory claims, hardlinks, 120 exact non-ELF/non-static-
  archive payloads and thirteen ELF/debug contracts match Make. These contracts
  cover twelve original installed programs plus the library DSO.
- `bazel-util-parent-no-tests-request-r1-20261106/inputs.json`,
  `bazel-util-parent-no-tests-native-r1-20261106` and
  `bazel-util-parent-no-tests-review-r1-20261106/review.json`: all 123 negative
  file/link records, runtime directory policy, 119 exact data files and one
  DSO ELF/debug contract match Make; no /usr/tests payload is installed. The
  source helper is not an original body execution.
- `bazel-util-tests-actions-r1-20261106/review.json`: six normal/private pairs of
  actual registered CppLink actions have identical expanded input file sets,
  configuration, environment and execution platform. Their argv differs only
  in output filename and the private inherited RPATH. The shared alwayslink
  archive appears in both actual inputs. This is not twelve executed links or
  a performance/cold-cache measurement. An initial audit incorrectly compared
  raw dep-set IDs; those are graph references. The final audit expands the
  complete input DAG and compares actual file identities.
- `bazel-util-tap-review-r1-20261106/review.json`: six copied original Kyua
  databases/stdout, loader receipts and runtime program copies are bound to
  final immutable test.log/XML hashes. SQLite read-only queries verify all six
  actual TAP main results are passed with no result reason. Strict trace-only
  checks resolve exactly native util/C/sys plus the VDSO; their library hashes
  match captured artifacts and executable hashes match retained program copies.
  These loader traces are separate from the Kyua body execution, not per-body
  tracing. The final expanded TAP assertions are recorded explicitly.

The final `bazel-util-tests-native-r2-20261106` changes the twenty ATF adapters
to consume the actual installed stripped program artifacts. All twenty ATF cases,
six TAP programs and source helper still pass. The final binding audit is
`bazel-util-tests-final-review-r1-20261106/review.json`: every captured output
remains byte-identical to the independently compared initial artifacts, and all
final report hashes verify. Copied TAP nested-result/trace evidence remains
explicitly bound to its original r1 execution, not silently relabeled as r2 data.

## Actual execution scope

All twenty original ATF cases pass, including the original unprivileged forkpty
process-limit case, cpuset parsing, number conversion, local-base environment,
login time conversion failures and wrapped login capability list ownership/
allocation failures. Those wrapped scenarios do not establish normal login/PAM
or SSH/service behavior. Original sources, case/user metadata and wrappers stay
intact; no authentication logic was rewritten to make these checks pass.

| Original TAP program | Planned assertions | Checked assertions | Original skips |
| --- | ---: | ---: | ---: |
| flopen_test | 5 | 5 | 0 |
| grp_test | 4 | 4 | 0 |
| humanize_number_test | 259 | 228 | 31 |
| pidfile_test | 5 | 5 | 0 |
| trimdomain_test | 6 | 6 | 0 |
| trimdomain-nodomain_test | 5 | 5 | 0 |
| Total | 284 | 253 | 31 |

The 31 original humanize skips remain skips, not passes. Their exact assertion
IDs and stdout are retained. Kyua's six passed TAP programs do not mean all 284
nested assertions executed. Hostname overrides and fault scenarios are original
source behavior; no host hostname/sysctl mutation was needed.

DOF initialization is disabled for isolated body checks. Native runfiles and
external/no-remote tags are declared. The ATF phase retains original defaults;
TAP uses the retained original SDK Kyua controller and private native programs.
No live provider firing, audit delivery, normal system boot or performance claim
follows. ELF checks cover PIE/interpreter/ordered dependencies/symbols/versions/
hardening/no installed RPATH; split-debug checks cover separation, installed name
and CRC. Raw DWARF/debugger-source, static archive equivalence, complete cache/
sandbox, reproducible bootstrap and resource/performance remain separate.

Continue remaining selected library/world test closure, full world/kernel/module/
pkgbase/debug, normal Capsule/service/SSH/PAM VM acceptance, CPU/RAM/disk-I/O/
footprint, bootstrap/cache/sandbox/reproducibility and verified combined base/
hardware publication. This is AMD64 evidence; cross-target installed runtime is
still open. No host installation, upgrade or reboot was performed.
