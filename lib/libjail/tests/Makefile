PACKAGE= libjail-tests
TESTSDIR= ${TESTSBASE}/lib/libjail
ATF_TESTS_C+= metadata_test
CFLAGS+= -I${SRCTOP}/lib/libjail
LIBADD= jail
NO_SHARED= yes
.include <bsd.test.mk>
