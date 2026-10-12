# SPDX-License-Identifier: BSD-2-Clause
#
# Generate FIDL bindings into the object tree at build time.
#
# FIDL_BINDINGS names binding sets; for each NAME set
#
#   FIDL_SCHEMAS.NAME	schema files, dependencies first and the library
#			last, relative to SRCTOP (or absolute)
#   FIDL_LIBRARY.NAME	the FIDL library name, e.g. bsd.time.v1
#   FIDL_FLAGS.NAME	extra fidlc arguments (optional), e.g. --available
#			bsd:2 for an evolution test's next schema
#
# and use
#
#   FIDLGEN.NAME	the include root: add -I${FIDLGEN.NAME} to CFLAGS for
#			<fidl/LIBRARY/c/bsd.h> and <fidl/LIBRARY/cpp/...>
#   FIDLGEN_SRCS.NAME	the generated sources to compile (natural and common
#			types, C bridge), relative to the object directory
#
# Generation runs in beforebuild, before anything is compiled, with fidlc
# (built in buildworld's bootstrap-tools stage) and Python (a build-only
# prerequisite checked by Makefile.inc1; override with PYTHON=).  Nothing
# generated is checked in or installed.  Include before <bsd.lib.mk>,
# <bsd.prog.mk> or <bsd.test.mk>.

.if !empty(FIDL_BINDINGS) && !defined(_FIDL_BINDINGS_MK_)
_FIDL_BINDINGS_MK_=

# buildworld passes PYTHON to the world stage; the top-level Makefile also
# exports the interpreter it found (_PYTHON_PATH) to every sub-make, which
# covers the compat-library stages.
.if !defined(PYTHON)
.if !empty(_PYTHON_PATH)
PYTHON=		${_PYTHON_PATH}
.else
PYTHON=		python3.12
.endif
.endif
FIDLC?=		fidlc
_FIDLGEN_DIR=	${SRCTOP}/tools/build/fuchsia
_FIDLGEN_TEMPLATES=	${SRCTOP}/contrib/fuchsia/tools/fidl/fidlgen_cpp/codegen
_FIDLGEN_TMPL=	file_markers file_common_types_header file_common_types_source \
		file_natural_types_header file_natural_types_source \
		natural_struct natural_table natural_union fragment_enum \
		fragment_bits fragment_const fragment_alias
# The generator and the templates it runs; a change regenerates every set.
_FIDLGEN_TOOLS=	${_FIDLGEN_DIR}/fidlgen-build.py \
		${_FIDLGEN_DIR}/generate-bsd.py \
		${_FIDLGEN_DIR}/generate_bsd_c.py \
		${_FIDLGEN_DIR}/generate_bsd_c_types.py \
		${_FIDLGEN_DIR}/fidlgen_natural.py \
		${_FIDLGEN_DIR}/fidlgen_reserved.py \
		${_FIDLGEN_DIR}/gotemplate.py \
		${_FIDLGEN_TMPL:@t@${_FIDLGEN_TEMPLATES}/${t}.tmpl@}
_FIDLGEN_FILES=	cpp/natural_types.cc cpp/common_types.cc c/bsd.cc
_FIDLGEN_HEADERS= cpp/markers.h cpp/common_types.h cpp/natural_types.h \
		cpp/bsd.h c/bsd.h c/bridge.h

fidlgen: .PHONY
beforebuild: fidlgen
beforedepend: fidlgen
CLEANDIRS+=	fidlgen

.for _s in ${FIDL_BINDINGS}
.if empty(FIDL_SCHEMAS.${_s}) || empty(FIDL_LIBRARY.${_s})
.error FIDL_BINDINGS entry ${_s} needs FIDL_SCHEMAS.${_s} and FIDL_LIBRARY.${_s}
.endif
FIDLGEN.${_s}=	${.OBJDIR}/fidlgen/${_s}
FIDLGEN_SRCS.${_s}= ${_FIDLGEN_FILES:@f@fidlgen/${_s}/fidl/${FIDL_LIBRARY.${_s}}/${f}@}
_FIDLGEN_INPUTS.${_s}= ${FIDL_SCHEMAS.${_s}:M/*} \
		${FIDL_SCHEMAS.${_s}:N/*:S,^,${SRCTOP}/,}
fidlgen/${_s}.stamp: ${_FIDLGEN_INPUTS.${_s}} ${_FIDLGEN_TOOLS}
	@mkdir -p ${.OBJDIR}/fidlgen
	${PYTHON} ${_FIDLGEN_DIR}/fidlgen-build.py --fidlc ${FIDLC} \
	    --out ${FIDLGEN.${_s}} --stamp ${.TARGET} \
	    ${FIDL_FLAGS.${_s}:@f@--fidlc-flag=${f}@} ${_FIDLGEN_INPUTS.${_s}}
fidlgen: fidlgen/${_s}.stamp
${FIDLGEN_SRCS.${_s}} \
    ${_FIDLGEN_HEADERS:@f@fidlgen/${_s}/fidl/${FIDL_LIBRARY.${_s}}/${f}@}: \
    fidlgen/${_s}.stamp
.NOPATH: fidlgen/${_s}.stamp ${FIDLGEN_SRCS.${_s}}
# The generator leaves unchanged files untouched, so a source can keep its
# old time while a header it includes (c/bridge.h) changes: rebuild every
# object of the set whenever the set is regenerated.
.for _f in ${FIDLGEN_SRCS.${_s}:R}
${_f}.o ${_f}.pico ${_f}.po ${_f}.pieo ${_f}.nossppico: fidlgen/${_s}.stamp
.endfor
.endfor
.endif
