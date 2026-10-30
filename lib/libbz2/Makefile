PACKAGE=	bzip2
LIB_PACKAGE=

BZ2DIR=	${SRCTOP}/contrib/bzip2
.PATH: ${BZ2DIR}

LIB=		bz2
SHLIB_MAJOR=	4
SRCS=		bzlib.c blocksort.c compress.c crctable.c decompress.c \
		huffman.c randtable.c
INCS=		bzlib.h
CFLAGS+=	-I${BZ2DIR}

WARNS?=		3

BZIP2_VERSION!=	sed -n '/bzip2\/libbzip2 version /{s/.*version //;s/ of.*//p;q;}' ${BZ2DIR}/bzlib.h

# Explicit generator inputs are shared with declared build actions.
BZIP2_PC_GENERATOR= gen-pc.sh
BZIP2_PC_PREFIX= /usr
BZIP2_PC_SED?= sed
BZIP2_PC_MV?= mv
BZIP2_PC_RM?= rm

# Configuration metadata for a template/output/tools/arguments generator.
PC_GENERATOR.bzip2.pc= ${.CURDIR}/${BZIP2_PC_GENERATOR}
PC_TEMPLATE.bzip2.pc= ${.CURDIR}/bzip2.pc.in
PC_DEPENDENCIES.bzip2.pc= ${BZ2DIR}/bzlib.h
PC_TOOLS.bzip2.pc= ${BZIP2_PC_SED} ${BZIP2_PC_MV} ${BZIP2_PC_RM}
PC_ARGS.bzip2.pc= ${BZIP2_PC_PREFIX:Q} '$${prefix}' ${LIBDIR:Q} \
    ${SHLIBDIR:Q} ${INCLUDEDIR:Q} ${BZIP2_VERSION:Q}

bzip2.pc: bzip2.pc.in ${BZIP2_PC_GENERATOR} ${PC_DEPENDENCIES.bzip2.pc}
	${SH:Ush} ${.CURDIR}/${BZIP2_PC_GENERATOR} ${.CURDIR}/bzip2.pc.in \
	    ${.TARGET} ${BZIP2_PC_SED:Q} ${BZIP2_PC_MV:Q} ${BZIP2_PC_RM:Q} \
	    ${PC_ARGS.bzip2.pc}

PCFILES=	bzip2.pc

.include <bsd.lib.mk>
