# Bazel shell compatibility audit

Scope: selected custom `devel/bazel9` 9.2.0_4 and its SHA256-verified 9.2.0
source archive, inspected 2026-10-24. This is a source audit; no Zsh compatibility
qualification or shell replacement has been performed.

## Three separate questions

1. **Building Bazel itself:** the port explicitly sets BAZEL_SH to its Bash
   path and invokes `compile.sh` using Bash. `compile.sh:1` has a Bash shebang;
   lines 36/46/63 source bootstrap scripts. `scripts/bootstrap/buildenv.sh:77`
   uses `BASH_SOURCE[0]`; lines 304–305 use Bash regex captures via
   `BASH_REMATCH[3]`. These are real shell semantics, not merely shebang labels.
   Replacing the interpreter name alone is not a supported conversion.
2. **Our own BSD targets:** the C/C++ pilot executes the staged compiler/linker
   through Bazel C++ actions, without wrapping Make or adding shell-based compile
   genrules. A system graph can minimize shell actions and express executable
   helpers with declared inputs. This does not prove Bazel's bootstrap or other
   actions no longer need Bash. Explicit `--shell_executable` is available for
   actions that honor the option; it does not rewrite script shebangs.
3. **Third-party Bazel projects:** projects may carry Bash sh_binary/sh_test
   scripts, genrules, repository rules and shell snippets, including absolute
   shebangs. Supporting arbitrary upstream projects means retaining their
   declared dependencies. Our BSD graph cannot establish their Zsh compatibility.

`src/main/java/com/google/devtools/build/lib/analysis/ShellConfiguration.java`
lines 73–89 defines `--shell_executable`, falls back to BAZEL_SH at server startup,
then defaults to `/usr/local/bin/bash` on FreeBSD. Its help explicitly warns that
shells incompatible with Bash can cause build or runtime failures.
`GenRuleBase.java:145` constructs a `source ...; ...` command.
`tools/genrule/genrule-setup.sh` has a Bash shebang and enables errexit, nounset
and pipefail. Those options alone are not the full compatibility contract.

## Path with limited downstream maintenance

Keep upstream Bash requirements for bootstrap and arbitrary third-party projects.
For our owned action scripts, prefer direct executable actions; where a shell is
needed, use an explicitly declared interpreter and test the actual scripts.
A targeted upstream-supported shell option is preferable to a downstream rewrite
of Bazel's bootstrap and ecosystem. Never install Zsh under a Bash pathname or
silently change upstream shebangs. Any proposed bootstrap conversion should be
upstreamable and maintained against the pinned Bazel release.

## Qualification required before making a change

- Bootstrap the selected Bazel release from its distribution using the proposed
  shell, build the complete Bazel executable and run its relevant bootstrap and
  shell tests. Capture argument/exit status behavior, not just syntax checks.
- Exercise arrays/indexing, parameter splitting, unmatched globs, regex capture,
  sourced-script location, traps, pipefail/errexit, command substitution, and
  quoting with spaces/empty arguments using actual affected scripts.
- Run genrule, sh_binary, sh_test, runfiles, repository rules, action environments,
  sandboxing and cross-execution tests. Include scripts with explicit Bash
  shebangs so an option override is not mistaken for interpreter replacement.
- Test representative unchanged third-party projects and Make-based ports.
  Unsupported Bash-dependent projects must retain a real Bash dependency.
- Compare resulting artifacts and performance against the Bash baseline.

The current host has no installed Zsh at `/bin/zsh`, `/usr/bin/zsh`, or
`/usr/local/bin/zsh`; a source-built object exists in the standard object tree.
Use the matching built system to qualify it. No host shell change is authorized
or needed for this investigation.

## Licensing

User accepts required GPL dependencies retaining their licenses. Removing Bash
would not establish that OpenJDK is the only GPL component: the JDK/runtime and
build-time dependency closures need their own license inventory. Preserve each
package's license and redistribution obligations; do not relabel imported tools
as BSD merely because they ship in the default system.

### Selected port dependency evidence (2026-10-24)

Evaluated `make -V RUN_DEPENDS -V LIB_DEPENDS -V BUILD_DEPENDS -V LICENSE`
against the selected custom ports tree, without installation:

- bazel9 runtime: Bash, OpenJDK21 and Python3.12; build additionally uses zip
  and Go1.26. Bazel itself declares APACHE20.
- OpenJDK21 build: Bash, autoconf, gsed, gmake, libiconv, zip, cups headers,
  pkgconf and X11 development dependencies. Its runtime includes the JVM wrapper,
  fonts/X11, ALSA, fontconfig, freetype, giflib, harfbuzz, lcms2, png and jpeg-turbo.
- Relevant port license declarations: Bash GPLv3+; gmake GPLv3; libiconv GPLv3;
  gsed GPLv3+ plus GFDL; autoconf EXCEPTION/GFDL/GPLv2+/GPLv3+ with multiple-license
  policy; OpenJDK21 GPLv2. ALSA is LGPL21+, a different license from GPL.

These are package-level declarations, not a complete file-level license audit.
OpenJDK exceptions and licenses of bundled components must be preserved from
its actual source/package notices. Build tools need not all ship in a runtime
image, whereas a default self-building development system needs its build
closure too. Removing only Bazel's Bash dependency does not remove OpenJDK's
Bash bootstrap requirement or these other GPL build dependencies. No conclusion
that OpenJDK is the only GPL component is supported. A recursive, pinned package
closure and bundled-component license inventory remain necessary before making
that claim; ports options and target architecture can change the closure.

For the owned version-map action we implemented a shell-free alternative:
explicit Clang preprocessing followed by an explicit AWK action, with a tiny
compiled stdout-redirection/exec helper. This removes a shell pipeline in that
particular BSD build action while preserving the maintained AWK generator. It
is not evidence that Bazel bootstrap or arbitrary projects work without Bash.
