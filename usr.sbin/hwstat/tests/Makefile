.include <src.opts.mk>

PACKAGE=	hwstat-tests

ATF_TESTS_SH=	hwstat_test
ATF_TESTS_C+=	sensors_test metrics_test sampling_test exec_timing_test
SRCS.exec_timing_test= exec_timing_test.c rapl.c sensors.c metrics.c format.c
CFLAGS.exec_timing_test+= -I${.CURDIR}/.. -I${SRCTOP}/lib/libotelexport
LIBADD.exec_timing_test+= otelexport m
SRCS.sampling_test= sampling_test.c rapl.c sensors.c metrics.c format.c
CFLAGS.sampling_test+= -I${.CURDIR}/.. -I${SRCTOP}/lib/libotelexport
LIBADD.sampling_test+= otelexport m
.PATH: ${.CURDIR}/..
SRCS.sensors_test=	sensors_test.c metrics.c

.if ${MACHINE_ARCH} == "amd64" || ${MACHINE_ARCH} == "i386"
ATF_TESTS_C+=	rapl_test
.endif

.include <bsd.test.mk>
