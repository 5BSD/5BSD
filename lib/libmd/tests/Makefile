PACKAGE=	tests

ATF_TESTS_SH=	libmd_test

MDTESTS=	md rmd sha skein

MDTESTS_md=	md4 md5
MDTESTS_rmd=	rmd160
MDTESTS_sha=	sha0 sha1 sha224 sha256 sha384 sha512 sha512t224 sha512t256
MDTESTS_skein=	skein256 skein512 skein1024

LIBADD=	md

.for mdt in ${MDTESTS}
REFS_${mdt}=	${MDTESTS_${mdt}:C/$/.ref/}
${PACKAGE}FILES+=	${REFS_${mdt}}

# This target is simply convenient for auditing, letting you build all of one
# digest suite with `make <family>driver`.
.PHONY: ${mdt}driver

. for mdtc in ${MDTESTS_${mdt}}
PROGS+=	${mdtc}driver
DIGESTS+=	${mdtc}

# Keep the source mapping explicit for both Make and alternative build graphs.
LIBMD_TEST_SOURCE_${mdtc}driver= ${mdt}driver.c

# Avoid obj collision, we'll build the same driver.c multiple times.
${mdtc}driver.c: ${LIBMD_TEST_SOURCE_${mdtc}driver}
	${CP} ${.ALLSRC} ${.TARGET}

SRCS_${mdtc}driver=	${mdtc}driver.c
BINDIR_${mdtc}driver=	${TESTSDIR}
.if ${mdt} == "sha"
CFLAGS_${mdtc}driver=	-DSHA=${mdtc:C/sha//:C/t//}
.else
CFLAGS_${mdtc}driver=	-D${mdt:tu}=${mdtc:C/${mdt}//}
.endif

${mdt}driver: ${mdtc}driver

. endfor
.endfor

LIBMD_TEST_GENERATOR= gen-tests.sh

CLEANFILES+=	libmd_test.sh
libmd_test.sh: Makefile ${LIBMD_TEST_GENERATOR}
	${SH:U/bin/sh} ${.CURDIR}/${LIBMD_TEST_GENERATOR} ${DIGESTS} > ${.TARGET}

.include <bsd.test.mk>
