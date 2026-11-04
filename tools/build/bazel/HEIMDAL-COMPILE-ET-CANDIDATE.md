# Heimdal libraries and compile_et: native candidate

## Graph

The maintained explicit Bazel inventory selects the original 59 roken C sources
and print_version.c for vers. Each has regular and PIE variants and own-object
component archives. Roken consumes the native generated platform header, original
public headers, private maintained configuration and OpenSSL headers. Its DSO
uses the original version script and soname libroken.so.11, with native crypt
and libc shared dependencies. Precise libc shared-object access is granted only
to the new roken package; program nonshared wrappers are not exported as DSO
inputs. Generated-header include mapping lives in its owning generator package.

compile_et uses native yacc/lex/m4 execution tools, explicit parser outputs and
private compiler headers. It dynamically consumes roken and statically consumes
the original internal vers library. Standard utility installation/debug/manual
and archive rules produce its kerberos-tagged contribution. The consumer remains
AMD64-only. The original root Heimdal profile stays explicitly incompatible:
adding this consumer does not complete other Heimdal programs or libraries.

## Evidence

All output roots are under /usr/obj/usr/src, dated 2026-11-04:

- bazel-heimdal-libraries-native-r2-20261104: regular/PIE archives and selected
  source-settings test pass using build-bsd bazel-test, 16 jobs.
- bazel-compile-et-native-r2-20261104: actual lexer/parser/shared link and
  installation manifest pass.
- bazel-compile-et-native-r3-20261104: component archive and CLI version test
  pass; version executes with declared native roken/crypt/md/libc/libsys runtime.
- bazel-compile-et-native-r4-20261104: final readable sources.bzl graph passes;
  selected tests pass again (this repeat may reuse cached results).
- The r4 candidate-review/review.json binds captured artifacts to verified
  receipts/manifests. Four archive member lists exactly match original Makefile
  source inventories in order (59 roken, one vers for each regular/PIE variant).
  Actual dynamic dependencies are retained in compile_et.dynamic.txt, including
  libroken.so.11. The consumer archive has three regular files with canonical
  unique member paths, and the executable/debug CRC binding passes.

The initial r1 library build correctly rejected a generated header mapped from
another package; mapping now belongs to make-roken. The initial consumer build
rejected undeclared visibility to libc DSO inputs; the fix grants precise package
access. Failed output roots are retained. Neither error was bypassed by relaxing
Bazel validation or substituting SDK library objects.

## Required follow-up

This does not prove original Make object/link/install equality. Fresh original
library references need an explicit binding to the already independently built
make-roken tool; no assumption that it is installed on the host is allowed.
Compare actual shared dependency order as well as objects and metadata. Exercise
successful/error error-table generation with original .et inputs, generated C/H
bytes and compiler consumption. Complete roken shared/static/header installation,
option/architecture coverage and full parent profiles before removing the gate.
No full world/pkgbase/bootstrap/runtime/performance acceptance is claimed.

The maintained frontend already accepts these explicit targets; its C source and
backend schema require no change. The manual and completion plan describe the
bounded result. Make remains default. BIP remains excluded.
