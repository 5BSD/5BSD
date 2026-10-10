PACKAGE= bsdmemory-tests
ATF_TESTS_C= pressure_test
SRCS.pressure_test= pressure_test.c pressure.c
CFLAGS+= -I${.CURDIR}/.. -I${SRCTOP}/lib/libnotify
.PATH: ${.CURDIR}/..
.include <bsd.test.mk>
