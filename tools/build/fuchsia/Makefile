# SPDX-License-Identifier: BSD-2-Clause
# Optional host-tool SDK. Bootstrap explicitly; never fetch while installing.
# (buildworld does not use this Makefile: it builds fidlc as a bootstrap tool
# from fidlc/ and generates the system's bindings with fidlgen-build.py.)
.include <src.opts.mk>
.MAIN: all
PACKAGE= libfidl
FIDL_TOOLS_OBJ?= /usr/obj/5bsd-fidl
PYTHON?= python3.12
GO?= go

FILESGROUPS= FIDL_COMMANDS FIDL_ADAPTER FIDL_HELPER FIDL_TEMPLATES \
    FIDL_NOTICE ICU_NOTICE
FIDL_COMMANDS= ${FIDL_TOOLS_OBJ}/fidlc ${FIDL_TOOLS_OBJ}/fidl-format \
    ${FIDL_TOOLS_OBJ}/fidl-lint
FIDL_COMMANDSDIR= /usr/bin
FIDL_ADAPTER= generate-bsd.py
FIDL_ADAPTERNAME= fidlgen-bsd
FIDL_ADAPTERDIR= /usr/bin
FIDL_HELPER= generate_bsd_c.py generate_bsd_c_types.py fidlgen_natural.py \
    fidlgen_reserved.py gotemplate.py
FIDL_HELPERDIR= /usr/libexec/fidl
# Upstream's fidlgen_cpp templates for the natural types (fidlgen_natural.py).
FIDL_TEMPLATES= ${FIDLGEN_TEMPLATES:@t@${SRCTOP}/contrib/fuchsia/tools/fidl/fidlgen_cpp/codegen/${t}.tmpl@}
FIDLGEN_TEMPLATES= file_markers file_common_types_header \
    file_common_types_source file_natural_types_header \
    file_natural_types_source natural_struct natural_table natural_union \
    fragment_enum fragment_bits fragment_const fragment_alias
FIDL_TEMPLATESDIR= /usr/libexec/fidl/templates
.for group in ${FILESGROUPS}
${group}PACKAGE= libfidl-tools
${group}MODE= 0555
.endfor
FIDL_HELPERMODE= 0444
FIDL_TEMPLATESMODE= 0444
# The tools embed Fuchsia code (BSD-2-Clause plus PATENTS) and the FXL ICU
# UTF helper (ICU license).
FIDL_NOTICE= ${SRCTOP}/contrib/fuchsia/LICENSE ${SRCTOP}/contrib/fuchsia/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libfidl-tools/fuchsia
ICU_NOTICE= ${SRCTOP}/contrib/fuchsia/src/lib/fxl/third_party/icu/LICENSE
ICU_NOTICEDIR= /usr/share/licenses/libfidl-tools/icu
.for group in FIDL_NOTICE ICU_NOTICE
${group}PACKAGE= libfidl-tools
${group}MODE= 0444
.endfor
MAN= fidlgen-bsd.1

.PHONY: bootstrap generators check check-bindings check-native check-soak \
    check-fuzz check-bench
bootstrap:
	${PYTHON} ${.CURDIR}/build-fidl.py --src ${SRCTOP} --obj ${FIDL_TOOLS_OBJ}
# Go is needed only for the conformance-test generator (gidl) and the Rust
# generator; nothing in buildworld or the C/C++ bindings uses it.
generators:
	${PYTHON} ${.CURDIR}/build-generators.py --src ${SRCTOP} --obj ${FIDL_TOOLS_OBJ} --go ${GO}
# Generate every binding set twice and require byte-identical output; check
# that each evolution test's next schema is additive at bsd:1.
check-bindings:
	${PYTHON} ${.CURDIR}/test-bindings.py --src ${SRCTOP} --tools ${FIDL_TOOLS_OBJ}
check: check-bindings
	${PYTHON} ${.CURDIR}/tests/import_test.py
	${PYTHON} ${.CURDIR}/tests/gotemplate_test.py
	${PYTHON} ${.CURDIR}/build-fidl.py --src ${SRCTOP} --obj ${FIDL_TOOLS_OBJ} --test-only

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
