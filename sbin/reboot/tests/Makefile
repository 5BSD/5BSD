.include <src.opts.mk>

PACKAGE= runtime-tests
TESTSDIR= ${TESTSBASE}/sbin/reboot
ATF_TESTS_C= reboot_test
CFLAGS+= -I${SRCTOP}/sys
LDFLAGS+= -Wl,--wrap=reboot -Wl,--wrap=kill -Wl,--wrap=sync \
	-Wl,--wrap=sleep -Wl,--wrap=execl -Wl,--wrap=geteuid \
	-Wl,--wrap=pututxline -Wl,--wrap=sysctlbyname

.include <bsd.test.mk>
