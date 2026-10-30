# SPDX-License-Identifier: BSD-2-Clause
#
# Generate protobuf bindings into the object tree at build time.
#
# PROTO_SETS names binding sets; for each NAME set
#
#   PROTO_FILES.NAME	.proto files, relative to PROTO_ROOT.NAME
#   PROTO_ROOT.NAME	their import root (absolute)
#   PROTO_LANG.NAME	upb (default): C for libupb, NAME.upb.h and
#			NAME.upb_minitable.{c,h}, from the protoc-gen-upb and
#			protoc-gen-upb_minitable plugins; upbdefs: the same
#			plus the reflection definitions NAME.upbdefs.{c,h}
#			(protoc-gen-upbdefs), for upb_DefPool, JSON and text
#			formats; or cpp: C++ for libprivateprotobuf,
#			NAME.pb.{cc,h}
#   PROTO_PATHS.NAME	further import roots (optional); the well-known
#			types (contrib/protobuf/src) are always importable
#
# and use
#
#   PROTOGEN.NAME	the include root of the generated files, added to
#			CFLAGS
#   PROTOGEN_SRCS.NAME	the generated sources, added to SRCS
#
# Generation runs in beforebuild, before anything is compiled, with the
# protoc and upb plugins built in buildworld's bootstrap-tools stage
# (Makefile.inc1), under ${SYSROOT}/legacy at the locations of
# lib/protobuf/protobuf.dirs.mk; outside a world build environment, the
# installed ${PROTOC_BINDIR}/protoc and plugins.  Override with PROTOC= and
# PROTOC_PLUGINS=.  Nothing generated
# is checked in or installed.  A upb set also adds the libupb include paths
# and LIBADD upb; a cpp set adds the protobuf include paths and LIBADD
# protobuf.  Include before <bsd.lib.mk>, <bsd.prog.mk> or <bsd.test.mk>.

.if !empty(PROTO_SETS) && !defined(_PROTOC_GEN_MK_)
_PROTOC_GEN_MK_=

.include "${SRCTOP}/lib/protobuf/protobuf.dirs.mk"
.if defined(SYSROOT) && exists(${SYSROOT}/legacy${PROTOC_BINDIR}/protoc)
_PROTOC_ROOT=	${SYSROOT}/legacy
.else
_PROTOC_ROOT=
.endif
PROTOC?=	${_PROTOC_ROOT}${PROTOC_BINDIR}/protoc
# Name the plugins explicitly when they are where they belong; otherwise
# protoc looks for protoc-gen-NAME on PATH.
.if !defined(PROTOC_PLUGINS)
PROTOC_PLUGINS=
.for _p in upb upb_minitable upbdefs
.if exists(${_PROTOC_ROOT}${PROTOC_PLUGINDIR}/protoc-gen-${_p})
PROTOC_PLUGINS+= --plugin=protoc-gen-${_p}=${_PROTOC_ROOT}${PROTOC_PLUGINDIR}/protoc-gen-${_p}
.endif
.endfor
.endif
_PROTOBUF_SRC=	${SRCTOP}/contrib/protobuf
_PROTOBUF_ABSL=	${SRCTOP}/contrib/abseil-cpp

protogen: .PHONY
beforebuild: protogen
beforedepend: protogen
CLEANDIRS+=	protogen

.for _s in ${PROTO_SETS}
PROTO_LANG.${_s}?=	upb
PROTOGEN.${_s}=		${.OBJDIR}/protogen/${_s}
.if ${PROTO_LANG.${_s}} == "upb" || ${PROTO_LANG.${_s}} == "upbdefs"
_PROTOGEN_OUT.${_s}=	${PROTO_FILES.${_s}:R:S/$/.upb.h/} \
			${PROTO_FILES.${_s}:R:S/$/.upb_minitable.h/} \
			${PROTO_FILES.${_s}:R:S/$/.upb_minitable.c/}
_PROTOGEN_CSRCS.${_s}=	${PROTO_FILES.${_s}:R:S/$/.upb_minitable.c/}
_PROTOC_OUT.${_s}=	--upb_out=${PROTOGEN.${_s}} \
			--upb_minitable_out=${PROTOGEN.${_s}}
.if ${PROTO_LANG.${_s}} == "upbdefs"
_PROTOGEN_OUT.${_s}+=	${PROTO_FILES.${_s}:R:S/$/.upbdefs.h/} \
			${PROTO_FILES.${_s}:R:S/$/.upbdefs.c/}
_PROTOGEN_CSRCS.${_s}+=	${PROTO_FILES.${_s}:R:S/$/.upbdefs.c/}
_PROTOC_OUT.${_s}+=	--upbdefs_out=${PROTOGEN.${_s}}
.endif
PROTOGEN_SRCS.${_s}=	${_PROTOGEN_CSRCS.${_s}:S/^/protogen\/${_s}\//}
_PROTOGEN_UPB=
# upb's inline accessors, which the generated code includes, cast away
# const and realign by design.
.for _f in ${_PROTOGEN_CSRCS.${_s}:T}
CWARNFLAGS.${_f}+=	-Wno-cast-qual -Wno-cast-align
.endfor
.elif ${PROTO_LANG.${_s}} == "cpp"
_PROTOGEN_OUT.${_s}=	${PROTO_FILES.${_s}:R:S/$/.pb.h/} \
			${PROTO_FILES.${_s}:R:S/$/.pb.cc/}
PROTOGEN_SRCS.${_s}=	${PROTO_FILES.${_s}:R:S/$/.pb.cc/:S/^/protogen\/${_s}\//}
_PROTOC_OUT.${_s}=	--cpp_out=${PROTOGEN.${_s}}
_PROTOGEN_CPP=
.else
.error PROTO_LANG.${_s}: unknown language ${PROTO_LANG.${_s}}
.endif
_PROTOGEN_FILES.${_s}=	${_PROTOGEN_OUT.${_s}:S/^/protogen\/${_s}\//}

# One protoc run writes the whole set; the first output stands for it.
# The inputs include the generator binaries, so a rebuilt protoc
# regenerates the set, and the Makefile naming the set, so files added to
# PROTO_FILES are generated in an existing object tree too.
_PROTOGEN_STAMP.${_s}=	protogen/${_s}/.stamp
${_PROTOGEN_STAMP.${_s}}: ${PROTO_FILES.${_s}:S/^/${PROTO_ROOT.${_s}}\//} \
		${.CURDIR}/Makefile
	@rm -rf ${PROTOGEN.${_s}}
	@mkdir -p ${PROTOGEN.${_s}}
	${PROTOC} ${PROTOC_PLUGINS} -I${PROTO_ROOT.${_s}} \
	    ${PROTO_PATHS.${_s}:S/^/-I/} -I${_PROTOBUF_SRC}/src \
	    ${_PROTOC_OUT.${_s}} \
	    ${PROTO_FILES.${_s}:S/^/${PROTO_ROOT.${_s}}\//}
	@touch ${.TARGET}
protogen: ${_PROTOGEN_STAMP.${_s}}
.for _f in ${_PROTOGEN_FILES.${_s}}
${_f}: ${_PROTOGEN_STAMP.${_s}}
.endfor

SRCS+=		${PROTOGEN_SRCS.${_s}}
CFLAGS+=	-I${PROTOGEN.${_s}}
DPSRCS+=	${_PROTOGEN_FILES.${_s}:M*.h}
# Objects built directly (make lib<name>.a, without beforebuild) must not
# compile before the bindings exist.
OBJS_DEPEND_GUESS+=	${_PROTOGEN_STAMP.${_s}}
.endfor

.if defined(_PROTOGEN_UPB)
# Generated upb code includes "upb/..." headers and the port definitions;
# the reflection headers include upb's bootstrap descriptor.upb.h.
CFLAGS+=	-I${_PROTOBUF_SRC} -I${_PROTOBUF_SRC}/upb/reflection/cmake
LIBADD+=	upb
.endif
.if defined(_PROTOGEN_CPP)
CFLAGS+=	-I${_PROTOBUF_SRC}/src
CXXFLAGS+=	-I${_PROTOBUF_ABSL}
LIBADD+=	protobuf
.endif

.endif
