# Current controlled full-kernel parity (2026-11-03)

## Result

The current amd64 GENERIC native build passes normal build-bsd format-5 through
kernel link, CTF merge and debug split. A fresh independent controlled Make build
passes separately. All 2,462 final-link objects have exact machine code,
allocated payloads/metadata (including addresses) and CTF bytes against that
control. This includes the separately committed CR0.WP startup fix in
sys/kern/init_main.c; the earlier result was not rebound to changed input bytes.

The full and runtime kernel comparisons pass all 56 allocated section contracts:
55 payloads are exact; the GNU SHA-1 build-ID note has the expected format but a
different value with nonallocated debug inputs. All 96,147 non-file loader symbol
identities and merged CTF bytes are exact. Whole-file kernel/debug equality is
not claimed. The maintained native debug test passes its positive and five
corruption/mode/name rejection cases; the original Make debug CRC also verifies.

## Actual inputs and independent control

The native compact log contains 2,465 actual CppCompile records, a fresh explicit
version action, the final link and merge. The configuration action is cached;
its captured output is not described as a fresh execution. All 2,462 ordered
link input files, parameters, the changed init compiler/dependency record,
generated configuration/version bodies and four final artifacts are retained
before another profile uses the shared state. Action records are streamed to
separate files rather than accumulated as a complete in-memory action list.

The declared source revision is 2c6c2e76e97bc08b42eb9980bdbd38ba369312fe. The
current compat-services SDK receipt is used unchanged. The new Make control
reads original current sources with the same explicit config/version inputs;
config.c, env.c, hints.c and vers.c match captured native bodies exactly. Original
Make rules, original tools, sixteen jobs and the previously documented three
compiler filename maps remain in use. No original generated C or objects are
copied into that control, and compiled outputs are not normalized.

5,241 native-recorded source/config/tool input hashes remain stable before/after
the independent Make build. Its 2,464 dependency files record 394,397 consumed
occurrences, including 5,068 unique source files. An initial audit found two
helper sources absent from the new primary before-build list: genassym.c and
genoffset.c. Their independently retained earlier hashes are explicitly bound
from the fresh configuration inventory and earlier ZFS original-control capture,
respectively. Current bytes match; the failed initial audit remains retained.
No missing-source hash is invented or rebound to current bytes.

The 121 external prerequisites consumed by original Make, including compiler
resource and host headers, are recorded separately. This does not establish a
fully hermetic original control, complete generator/toolchain/bootstrap closure,
or general SDK/cache performance qualification.

## Maintained workflow and limits

Existing build-bsd format-5 inputs and native kernel rules carry the entire
build; no frontend-C, shared rule, production default, signing or publication
policy changes are needed for this refresh. The qualification manual and roadmap
are updated. Make stays production/default; BIP stays excluded. No host kernel
installation, module loading, upgrade, reboot or VM boot is performed.

Next build all 729 selected amd64 modules together and qualify installation/
pkgbase closure. ARM64/RISC-V and other configurations, complete world/rescue/
stand, bootstrap, hardware/combined publication, debugger source lookup,
sandboxing, VM/runtime and measured CPU/memory/disk/cache gates remain open.
Full separate DWARF equality and actual debugger source resolution remain
explicitly unqualified despite valid debug CRCs.

Evidence roots under /usr/obj/usr/src:

- bazel-kernel-current-config-reference-r1-20261103: independent current
  selection and changed-source audit, including initial location-bearing record
  comparison and corrected ordered object-identity comparison.
- bazel-kernel-current-full-link-native-r1-20261103: normal frontend receipt,
  compact execution log and immutable four-artifact capture.
- bazel-kernel-current-full-link-capture-r1-20261103: actual action manifest,
  streamed records, all ordered input objects, parameters and generated bodies.
- bazel-kernel-current-canonical-make-control-r1-20261103: independent controlled
  original build, explicit policy, commands, source hashes and resource output.
- bazel-kernel-current-full-parity-review-r1-20261103: all-object comparisons,
  full/runtime allocated/symbol/CTF results, debug checks, dependency audit and
  explicit supplemental pre-build bindings with the original failed audit.
