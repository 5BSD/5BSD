PACKAGE= bsdmemory-tests
ATF_TESTS_C= pressure_test
SRCS.pressure_test= pressure_test.c pressure.c
CFLAGS+= -I${.CURDIR}/.. -I${SRCTOP}/lib/libnotify
.PATH: ${.CURDIR}/..
ATF_TESTS_C+= dependency_test
SRCS.dependency_test= dependency_test.c pressure.c
CFLAGS.dependency_test+= -I${SRCTOP}/lib/libservice -I${SRCTOP}/lib/libsysctlcmp
LIBADD.dependency_test= notify service sysctlcmp
NO_SHARED.dependency_test= yes
LDFLAGS.dependency_test+= -Wl,--wrap=sysctlcmp_client_open \
    -Wl,--wrap=sysctlcmp_client_close -Wl,--wrap=sysctlcmp_get \
    -Wl,--wrap=notify_client_open_system -Wl,--wrap=notify_client_close \
    -Wl,--wrap=notify_state_get -Wl,--wrap=notify_state_set
.include <bsd.test.mk>
