.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	capbundle
SHLIB_MAJOR=	2
MAN=	libcapbundle.3

SRCS=	libcapbundle.c libcapbundle_parse.c libcapbundle_verify.c \
	principal_policy.c
INCS=	libcapbundle.h

FILESGROUPS+=	examples
examples=	examples/blued.ucl \
		examples/meshd.ucl
examplesDIR=	${SHAREDIR}/examples/libcapbundle
examplesPACKAGE=	lib${LIB}

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/lib/libauthorityrt
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		authorityrt ucl md

.include <bsd.lib.mk>
