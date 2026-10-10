PACKAGE= libcache-tests
ATF_TESTS_C= cache_test
CFLAGS+= -I${.CURDIR}/.. -I${SRCTOP}/lib/libnotify -I${SRCTOP}/lib/libservice
LIBADD= service pthread
NO_SHARED= yes
.include <bsd.test.mk>
