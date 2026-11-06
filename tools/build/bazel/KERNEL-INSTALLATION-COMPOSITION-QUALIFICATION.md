# Current AMD64 complete kernel installation qualification

Date: 2026-11-06. Scope: installation composition, not a booted or published system.

## Implementation

`//sys/amd64/conf:complete_install_archive` joins typed kernel/GDB directory
policy with `//sys/modules:amd64_base_installation`, then installs generated
`linker.hints`. Components retain the same actual declared payload Files; no
staged filesystem discovery or generated BUILD inventory replaces source rules.
`complete_kernel_payload`, `complete_kernel_hints` and `complete_install_manifest`
expose the intermediate typed records for further package composition.

`bsd_linker_hints` selects the regular direct children that original kldxref would
scan (names without a dot, or ending in .ko), resolves declared hardlinks, and
keeps installation symlinks out of its ELF inputs, matching FTS_PHYSICAL behavior.
The action uses source-built execution-configured kldxref and declared DSOs plus
SDK Python/runtime. It streams only selected ELFs into a private directory for
kldxref's existing regular-file-only explicit `-o` API. It atomically publishes
hints after success and removes temporary copies. These copies consume build-time
I/O and disk space; this is not an accepted performance result or a runtime change.

A native Bazel test compares generated hints with both ordinary directory mode
and explicit-input mode, preserving aliases and ignoring debug files. It checks
that an undeclared extra file cannot enter explicit mode, declared invalid ELF,
duplicate and symlink inputs fail, existing output survives failure, temporary
output is cleaned and all inputs remain unchanged. Target ELFs are inspected by
the execution tool; the test does not execute a target kernel or module.

`kernel_base_directory` and `kernel_debug_directory` select layout; an empty debug
prefix remains supported by the existing installation rules. The new label flag
`//tools/build/bazel/config:kernel_directory_policy` defaults to an empty filegroup.
Both component kernel archives and the complete archive accept this declared
supplemental mtree source. Custom ancestors absent from maintained mtree must be
supplied explicitly; no host permissions or inferred directory defaults fill gaps.
The relocation fixture is source policy under `tests/kernel_installation`; it is
not the maintained system default. Default-layout analysis fixtures now explicitly
select their own default settings, as the existing custom/inline fixtures do.

## Reproduction and evidence

All paths below are under `/usr/obj/usr/src`. Each final format-5 request uses
16 jobs through maintained `build-bsd bazel-test`, explicit source revision
35901b884a2c7061a55686e7788bda7a7a036e0c-dirty, Bazel 9.3.1 and the declared
world-pkg SDK/JDK inputs. The historical candidate executable name does not select
BIP or ZFS behavior. Equivalent commands use the maintained frontend with:

```
build-bsd bazel-test --arch amd64 --jobs 16 \
  --bazel-inputs /usr/obj/usr/src/<request>/inputs.json \
  --output /usr/obj/usr/src/<fresh-output>
```

| Profile | Request | Final native result | Independent review |
| --- | --- | --- | --- |
| Default | bazel-kernel-composition-default-request-r4-20261106 | bazel-kernel-composition-default-native-r4-20261106 | bazel-kernel-composition-default-review-r5-20261106 |
| No separate debug | bazel-kernel-composition-nodebug-request-r3-20261106 | bazel-kernel-composition-nodebug-native-r2-20261106 | bazel-kernel-composition-nodebug-review-r1-20261106 |
| Relocated | bazel-kernel-composition-relocated-request-r4-20261106 | bazel-kernel-composition-relocated-native-r3-20261106 | bazel-kernel-composition-relocated-review-r1-20261106 |

Each final native receipt is passed with 21 selected test targets. Cached results
are accepted and reported; these are not 63 newly executed tests. Native hints
were executed during development/final profile construction. Kernel CTF is true
in all three requests; GENERIC requests WITH_CTF for DTrace.

All archives pass exhaustive membership, file and directory ownership/mode/epoch,
alias, declared payload SHA-256, kernel/module ELF identity, retained loader symbol
table, absence of runtime DWARF, nonempty CTF and debug pairing/CRC checks.
Module membership and owner policy reuse the independent full source Make audit
from ROOT-MODULE-GRAPH-QUALIFICATION.md, hash
22e8b5e5dddf4fed4736f48bbdcefafa51aac41ca3fb3d56b34f2a6ea209e35a.
A new observer queries original kern.post.mk GDB_FILES and installation defaults
through the retained generated Makefile; GDB source bytes match unchanged scripts.
No Make invocation participates in the native production graph.

Default and relocated archives each contain 1,453 regular files, three aliases,
and respectively nine/eight physical directories; the no-debug archive has 724
regular files, three aliases and three directories. Every profile contains the
kernel plus 722 modules, all 723 with CTF. Default/relocated regular payload size
is 786,066,680 bytes; no-debug is 168,653,788 bytes (not allocated filesystem size).
Across profiles all allocated ELF sections and CTF match exactly; relocation also
preserves every regular payload byte after destination-prefix mapping.

The aggregate comparison plus retained observer scripts is
`bazel-kernel-composition-review-r1-20261106`. Its `review.json` SHA-256 is
5ac83e5ff62d26dbfe1ad1fd3fb53eed150e3f95fe8ba308ed0ad6d121def181.
Per-profile reviews bind captured receipt, manifest and artifact SHA-256 values.
Scripts are retained with evidence so the independent observation is reproducible;
they are not another production build path.

## Retained failures and review corrections

The initial default request lacked the mandatory explicit kernel source revision;
analysis rejected it. Default native r2 passed before the new hints Python launcher
explicitly bound its declared runtime library search path; r3 and final r4 include
the fix. Earlier default/nodebug captures did not explicitly retain kernel/debug
producer outputs separately; final requests include them for independent byte
comparison rather than relying on mutable bazel-bin paths.

Relocated native r1 failed because /debug, /debug/qualification and its boot
ancestor were absent from source directory policy. It remains a useful negative
case. The explicit policy input fixes that failure without weakening archive checks.
The frontend refused an overlapping attempted qualification while the previous
build lock was held; final matrix runs were sequential after terminal completion.
Early independent observer runs used the wrong inventory status vocabulary,
misread Make's absolute alias destinations, or lacked separately captured kernel
outputs. Final observers correct those assumptions and check the full archive;
no expected membership or producer policy was reduced to obtain a pass.

## Frontend and remaining work

Existing format-5 target/settings/test APIs carry these targets and label policy;
`build-bsd.c` needs no new option or bypass. Backend signing, staging verification
and publication policy are unchanged. The frontend manual describes these inputs
in the same change. Bundle signing does not establish verified boot or protection
against compromised root.

This is not final pkgbase packaging, normal system startup, SSH/PAM/login, a genuine
version upgrade or a cross/custom-kernel acceptance result. Packaging still must
project kernel package ownership into KERNCONF/flavor families, preserve non-kernel
module assignments merged into world packages, and reconcile full directory policy.
Original mtree-to-plist.awk currently classifies kernel debug payloads by a fixed
/usr/lib/debug/boot prefix; general package layouts require correcting that source
policy with explicit inputs and parity checks. Root FDT/MMCCAM/TESTS branches and
MODULES_OVERRIDE/EXTRA/WITHOUT_MODULES/ALL_MODULES remain incomplete.

Full bootstrap, cache/incremental and sandbox enforcement, reproducibility, actual
debugger behavior, CPU/RAM/disk I/O/space comparison, separate hardware builds and
verified combined publication remain acceptance gates. Make remains production
and default. BIP is excluded. No host install, module load, upgrade or reboot ran.
