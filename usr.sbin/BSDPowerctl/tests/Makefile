PACKAGE= runtime-tests
TESTSDIR= ${TESTSBASE}/usr.sbin/BSDPowerctl
ATF_TESTS_C+= duration_test
CFLAGS+= -I${SRCTOP}/lib/libpowercmp -I${SRCTOP}/lib/libservice
LIBADD.duration_test= powercmp fidl_bsd channel service
NO_SHARED.duration_test= yes
.include <bsd.test.mk>
