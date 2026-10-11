# SPDX-License-Identifier: BSD-2-Clause
#
# fidlc, the upstream FIDL compiler, as a build tool: buildworld builds it in
# the bootstrap-tools stage (Makefile.inc1) and the library Makefiles run it,
# through lib/libfidl/fidl-bindings.mk, to generate FIDL bindings into the
# object tree.  It is never installed into the target.  The import is
# patched (tools/build/fuchsia/patches/fuchsia-fidlc-bootstrap.patch) to use
# <regex> instead of RE2 and libmd instead of OpenSSL, so it needs only a
# C++20 compiler and the bootstrapped libmd on any build host.

FUCHSIA=	${SRCTOP}/contrib/fuchsia
FIDLC_SRC=	${FUCHSIA}/tools/fidl/fidlc

PROG_CXX=	fidlc
BINDIR=		/usr/bin
MAN=
CXXSTD=		c++20
WARNS?=		0

.PATH: ${FIDLC_SRC}/cmd/fidlc ${FIDLC_SRC}/src ${FUCHSIA}/src/lib/cmdline \
    ${FUCHSIA}/sdk/lib/zircon-assert ${FUCHSIA}/src/lib/fxl/strings \
    ${FUCHSIA}/src/lib/fxl/third_party/icu

SRCS=	main.cc
# The compiler proper; the linter, formatter and their helpers stay out.
SRCS+=	attribute_schema.cc attributes.cc availability_step.cc \
	compile_step.cc compiler.cc constraints.cc consume_step.cc \
	diagnostic_types.cc diagnostics_json.cc experimental_flags.cc \
	flat_ast.cc index_json_generator.cc json_generator.cc lexer.cc \
	name.cc names.cc parser.cc raw_ast.cc reference.cc \
	replacement_step.cc reporter.cc resolve_step.cc source_file.cc \
	source_manager.cc source_span.cc transport.cc tree_visitor.cc \
	type_resolver.cc type_shape_step.cc types.cc typespace.cc utils.cc \
	values.cc verify_steps.cc versioning_types.cc virtual_source_file.cc
SRCS+=	json_schema.cc args_parser.cc zx_panic_libc.cc
SRCS+=	ascii.cc concatenate.cc split_string.cc string_number_conversions.cc \
	string_printf.cc substitute.cc trim.cc utf_codecs.cc icu_utf.cc

CXXFLAGS+=	-I${FUCHSIA} -I${FUCHSIA}/sdk/lib/fit/include \
		-I${FUCHSIA}/sdk/lib/stdcompat/include \
		-I${FUCHSIA}/src/lib/cmdline/include \
		-I${FUCHSIA}/zircon/system/public

# The --json-schema output: the schema embedded as a string.
json_schema.cc: ${FIDLC_SRC}/gen-json-schema.sh ${FIDLC_SRC}/schema.json
	sh ${FIDLC_SRC}/gen-json-schema.sh ${.TARGET} ${FIDLC_SRC}/schema.json
CLEANFILES+=	json_schema.cc

LIBADD=		md

.include <bsd.prog.mk>
