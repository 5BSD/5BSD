# SPDX-License-Identifier: BSD-2-Clause
# Optional host-tool SDK. Bootstrap explicitly; never fetch while installing.
.include <src.opts.mk>
.MAIN: all
PACKAGE= libfidl
FIDL_TOOLS_OBJ?= /usr/obj/5bsd-fidl
PYTHON?= python3.12
GO?= go

FILESGROUPS= FIDL_COMMANDS FIDL_GENERATOR FIDL_ADAPTER FIDL_HELPER \
    FIDL_NOTICE ICU_NOTICE GO_NOTICE
FIDL_COMMANDS= ${FIDL_TOOLS_OBJ}/fidlc ${FIDL_TOOLS_OBJ}/fidl-format \
    ${FIDL_TOOLS_OBJ}/fidl-lint
FIDL_COMMANDSDIR= /usr/bin
FIDL_GENERATOR= ${FIDL_TOOLS_OBJ}/fidlgen_cpp
FIDL_GENERATORDIR= /usr/libexec/fidl
FIDL_ADAPTER= generate-bsd.py
FIDL_ADAPTERNAME= fidlgen-bsd
FIDL_ADAPTERDIR= /usr/bin
FIDL_HELPER= generate_bsd_c.py generate_bsd_c_types.py
FIDL_HELPERDIR= /usr/libexec/fidl
.for group in ${FILESGROUPS}
${group}PACKAGE= libfidl-tools
${group}MODE= 0555
.endfor
FIDL_HELPERMODE= 0444
# The tools embed Fuchsia code (BSD-2-Clause plus PATENTS), the FXL ICU UTF
# helper (ICU license) and, in fidlgen_cpp, the Go runtime (BSD-3-Clause,
# license captured from the bootstrap toolchain).
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libfidl-tools/fuchsia
ICU_NOTICE= ${SRCTOP}/contrib/fuchsia/src/lib/fxl/third_party/icu/LICENSE
ICU_NOTICEDIR= /usr/share/licenses/libfidl-tools/icu
GO_NOTICE= ${FIDL_TOOLS_OBJ}/go/LICENSE
GO_NOTICEDIR= /usr/share/licenses/libfidl-tools/go
.for group in FIDL_NOTICE ICU_NOTICE GO_NOTICE
${group}PACKAGE= libfidl-tools
${group}MODE= 0444
.endfor
MAN= fidlgen-bsd.1

.PHONY: bootstrap check check-native check-soak check-fuzz check-bench
bootstrap:
	${PYTHON} ${.CURDIR}/build-fidl.py --src ${SRCTOP} --obj ${FIDL_TOOLS_OBJ}
	${PYTHON} ${.CURDIR}/build-generators.py --src ${SRCTOP} --obj ${FIDL_TOOLS_OBJ} --go ${GO}
check:
	${PYTHON} ${.CURDIR}/test-bindings.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ}
	${PYTHON} ${.CURDIR}/tests/import_test.py
	${PYTHON} ${.CURDIR}/build-fidl.py --src ${SRCTOP} --obj ${FIDL_TOOLS_OBJ} --test-only
	${PYTHON} ${.CURDIR}/build-generators.py --src ${SRCTOP} --obj ${FIDL_TOOLS_OBJ} --go ${GO} --test

# Native CI: requires a matching 5BSD kernel and already bootstrapped tools.
check-native:
	${PYTHON} ${.CURDIR}/test-bindings.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ}
	${PYTHON} ${.CURDIR}/build-runtime.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ} --test
	${PYTHON} ${.CURDIR}/build-runtime.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ} --test --sanitize
	${PYTHON} ${.CURDIR}/test-installed.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ} --packages
	${PYTHON} ${.CURDIR}/test-provider.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ} --packages
	${PYTHON} ${.CURDIR}/test-provider.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ} --sanitize

# Opt-in sustained resource checks, separate from the ordinary CI suite.
FIDL_SOAK_SECONDS?= 600
FIDL_SANITIZER_SOAK_SECONDS?= 300
check-soak:
	${PYTHON} ${.CURDIR}/test-provider.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ} --soak-seconds ${FIDL_SOAK_SECONDS}
	${PYTHON} ${.CURDIR}/test-provider.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ} --sanitize --soak-seconds ${FIDL_SANITIZER_SOAK_SECONDS}

# Native coverage-guided fuzzing uses an isolated instrumented object tree.
FIDL_FUZZ_SECONDS?= 300
check-fuzz:
	${PYTHON} ${.CURDIR}/build-runtime.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ} --fuzz
	${PYTHON} ${.CURDIR}/fuzz-runtime.py --seconds ${FIDL_FUZZ_SECONDS}

# Comparative raw-libchannel/C++/C request-reply measurement (-O2 tree).
# Run on an otherwise idle host; results are written to bench/bench.json.
FIDL_BENCH_CALLS?= 20000
check-bench:
	${PYTHON} ${.CURDIR}/build-runtime.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ} --bench --bench-calls ${FIDL_BENCH_CALLS}

.include <bsd.prog.mk>
