.include <src.opts.mk>

PACKAGE=	hwstat-tests

ATF_TESTS_SH=	hwstat_test
ATF_TESTS_C+=	sensors_test metrics_test sampling_test exec_timing_test
SRCS.exec_timing_test= exec_timing_test.c rapl.c sensors.c metrics.c format.c
LIBADD.exec_timing_test+= otelexport m
SRCS.sampling_test= sampling_test.c rapl.c sensors.c metrics.c format.c
LIBADD.sampling_test+= otelexport m
.PATH: ${.CURDIR}/..
# format.c etc. are shared by several test programs; their objects can be built
# outside any one program's flags, so the include paths must be global.
CFLAGS+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libotelexport
SRCS.sensors_test=	sensors_test.c metrics.c

.if ${MACHINE_ARCH} == "amd64" || ${MACHINE_ARCH} == "i386"
ATF_TESTS_C+=	rapl_test
.endif

.include <bsd.test.mk>
