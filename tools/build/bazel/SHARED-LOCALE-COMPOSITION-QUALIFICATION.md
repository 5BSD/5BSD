# Shared locale composition and execution dependency qualification

## Native graph (2026-11-05)

`//share:locale_installation_archives` composes the ten maintained locale
components using existing source-owned definitions. The unconditional ctypedef
component preserves runtime C.UTF-8; the other nine components follow the locales
setting, matching share/Makefile traversal. This is a locale parent, not a
complete share/world endpoint. The independently existing i18n encoding archive
is included alongside it in qualification.

Review of observed localedef actions found that the executable and source data
were declared, but its dynamic execution runtime was missing. CTYPE and collation
actions now declare execution-platform SDK libc, libsys and loader inputs, use
the tool's FilesToRunProvider and explicitly set the runtime library search path.
The native execution localedef has one direct NEEDED library, libc. This change
makes those runtime bytes part of the action dependency/cache key; it does not
claim to virtualize the host kernel or the ELF interpreter path.

The archive helpers now grant only the intended share parent package visibility.
No dependency checks are bypassed. No Python implementation, Make interpretation,
source inventory snapshot or host dataset fallback is added. Existing native
source/alias inventories, vendor data and target byte-order choices are retained.
Current locale generation remains qualified only for AMD64. Its x86-only target
selections still need ARM64/RISC-V implementation and qualification.

## Complete original comparisons

All evidence below is under `/usr/obj/usr/src/`.

The final native capture is `bazel-shared-locales-native-r4-20261105`; its request
is `bazel-shared-locales-request-r2-20261105/inputs.json`. The maintained frontend
runs sixteen jobs and the selected source-settings Bazel test passes.
`bazel-shared-locales-original-review-r2-20261105/review.json` retains the exact
comparison source, hashes and native receipt/manifest/artifact bindings.

| Owner | Metadata records | Regular file payloads | Symlinks |
| --- | ---: | ---: | ---: |
| ctypedef | 391 | 28 | 167 |
| colldef | 229 | 113 | 1 |
| colldef_unicode | 161 | 40 | 40 |
| monetdef | 229 | 56 | 58 |
| monetdef_unicode | 161 | 55 | 25 |
| msgdef | 221 | 44 | 66 |
| msgdef_unicode | 161 | 42 | 38 |
| numericdef | 227 | 10 | 103 |
| numericdef_unicode | 161 | 8 | 72 |
| timedef | 389 | 124 | 70 |
| i18n | 722 | 687 | 0 |
| Total | 3052 | 1207 | 640 |

The 1205 remaining records are directory claims, including repetitions between
components. The audit compares each complete component separately; it does not
claim 3052 unique installed paths or resolve whole-world directory/package
ownership. Each component passes inventory, owner/group, modes, tags, flags,
exact staged file bytes and METALOG size/hash, symlink targets and tar serialization.

Fresh original locale references are `bazel-shared-<owner>-make-r1-20261105`,
except ctypedef and msgdef use r2 after their visibility changes. Original stages
use the unchanged selected SDK/profile and sixteen jobs, with tests disabled.
The i18n comparison reuses the independent `bazel-i18n-make-20261101` reference
from ICONV-RUNTIME-QUALIFICATION.md; its recorded component source hashes are
rechecked against current files. It is not presented as a fresh Make execution.
Native generation uses source-built tools; the original reference executes its
maintained recipes in the recorded reference environment, not an independent
reproducible compiler/generator bootstrap.

## Minimal selection and actual action evidence

`bazel-shared-locales-minimal-native-r1-20261105` selects exactly the CTYPE archive.
`bazel-shared-ctypedef-minimal-make-r2-20261105` independently stages original Make
with LOCALES disabled. `bazel-shared-locales-minimal-review-r1-20261105/review.json`
passes its complete three records: one C.UTF-8 file and two directory claims.
The runtime file package remains runtime; its directory tags preserve Make's
utilities ownership policy.

`bazel-shared-locales-dependency-review-r1-20261105/review.json` checks logs using
the bound upstream execution-log converter. All 181 observed localedef actions
(28 CTYPE plus 153 collation) execute with declared execution libc/libsys/loader
inputs and explicit library search paths. All eleven archive and both metadata
outputs remain byte-identical to the pre-change component capture
`bazel-shared-locales-native-r1-20261105`. Native archive parity was rechecked
against original Make after composing the parent and closing runtime inputs.
The observed runner is processwrapper-sandbox, not proof of complete OS isolation.

`bazel-shared-locales-cached-native-r1-20261105` repeats the full request after
switching to the minimal profile. The reuse audit
`bazel-shared-locales-reuse-review-r1-20261105/review.json` verifies all 33 output
hashes, actual parent selection and both execution logs: no uncached share spawns.
This proves bounded unchanged-request reuse, not a cold compiler bootstrap or
comprehensive input-mutation/performance qualification.

The first parent attempts r2 and r3 failed actual Bazel visibility checks. Those
captures remain failed. The helpers were corrected to expose their intended
parent; r4 is the accepted native composition evidence. No ignore-visibility flag
or comparison exception was introduced.

`bazel-shared-locales-namespace-r1-20261105/review.json` reconciles this capture
with the preceding production component captures: 1158 unique archives and 30736
non-directory paths, zero conflicting file claims. It is not a combined world
build, directory ownership reconciliation or pkgbase acceptance.

## Maintained frontend and remaining work

The normal format-5 build-bsd target/scalar-setting interface and standard archive
output groups already support this parent. Its manual documents the locale
selection/runtime dependency behavior. No dispatcher, signing/staging/verification
or publication-helper change is needed. Runs are unsigned development qualification;
no publication, host installation, upgrade or reboot was performed.

Complete share/world parents, installed tests, complete installation/debug/pkgbase
parity, ARM64/RISC-V and other configurations, reproducible bootstrap/package
inputs, runtime/VM and comparative CPU/memory/disk gates remain required. The
previous iconv VM evidence is separate and bounded; this checkpoint does not prove
all locale runtime behavior. Message-catalog generation is outside the changed
localedef actions. Make remains production/default and remains available for
ports. BIP stays excluded.
