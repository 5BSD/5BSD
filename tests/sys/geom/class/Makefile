.include <src.opts.mk>

PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/geom/class

.if ${MK_OPENSSL} != "no"
TESTS_SUBDIRS+=	eli
.endif
TESTS_SUBDIRS+=	gate
TESTS_SUBDIRS+=	label
TESTS_SUBDIRS+=	mirror
TESTS_SUBDIRS+=	multipath
TESTS_SUBDIRS+=	nop
TESTS_SUBDIRS+=	part
TESTS_SUBDIRS+=	uzip
TESTS_SUBDIRS+=	zoned

${PACKAGE}FILES+=	geom_subr.sh
${PACKAGE}FILES+=	zoned_subr.sh

.include <bsd.test.mk>
