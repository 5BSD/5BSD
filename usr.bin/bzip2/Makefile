PACKAGE=	bzip2

BZ2DIR=	${SRCTOP}/contrib/bzip2
.PATH: ${BZ2DIR}

PROG=	bzip2
CFLAGS+= -D_FILE_OFFSET_BITS=64

WARNS?=	3

LIBADD=	bz2

LINKS=	${BINDIR}/bzip2 ${BINDIR}/bunzip2
LINKS+=	${BINDIR}/bzip2 ${BINDIR}/bzcat
MLINKS=	bzip2.1 bunzip2.1 \
	bzip2.1 bzcat.1 \
	bzip2.1 bzip2recover.1

BZIP2_TEST_CASES= sample1 sample2 sample3
BZIP2_TEST_COMPRESS.sample1= -1
BZIP2_TEST_COMPRESS.sample2= -2
BZIP2_TEST_COMPRESS.sample3= -3
BZIP2_TEST_DECOMPRESS.sample1= -d
BZIP2_TEST_DECOMPRESS.sample2= -d
BZIP2_TEST_DECOMPRESS.sample3= -ds

REFFILES= ${BZIP2_TEST_CASES:S/$/.ref/}
DREFFILES= ${BZIP2_TEST_CASES:S/$/.bz2/}
TESTFILES= ${REFFILES} ${DREFFILES}

CLEANFILES+= ${TESTFILES} \
	${BZIP2_TEST_CASES:S/$/.rb2/} ${BZIP2_TEST_CASES:S/$/.tst/}

.for f in ${REFFILES}
${f}:	${f}.gz.uu
	uudecode -p ${BZ2DIR}/${f}.gz.uu | gunzip > ${f}
.endfor
.for f in ${DREFFILES}
${f}:	${f}.uu
	uudecode ${BZ2DIR}/${f}.uu
.endfor

test:  bzip2 ${TESTFILES}
	@cat ${BZ2DIR}/words1
.for case in ${BZIP2_TEST_CASES}
	./bzip2 ${BZIP2_TEST_COMPRESS.${case}} < ${case}.ref > ${case}.rb2
.endfor
.for case in ${BZIP2_TEST_CASES}
	./bzip2 ${BZIP2_TEST_DECOMPRESS.${case}} < ${case}.bz2 > ${case}.tst
.endfor
.for case in ${BZIP2_TEST_CASES}
	cmp ${case}.bz2 ${case}.rb2
.endfor
.for case in ${BZIP2_TEST_CASES}
	cmp ${case}.tst ${case}.ref
.endfor
	@cat ${BZ2DIR}/words3

.include <bsd.prog.mk>
