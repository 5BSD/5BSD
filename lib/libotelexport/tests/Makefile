.include <src.opts.mk>

PACKAGE=	libotelexport-tests

ATF_TESTS_C=	otelexport_test

# otel.conf(5) system configuration layer.
ATF_TESTS_C+=	sysconf_test
# Allocation-failure sweep: links a failalloc-instrumented oe_sysconf.c.
ATF_TESTS_C+=	sysconf_oom_test
SRCS.sysconf_oom_test=	sysconf_oom_test.c sysconf_oom_unit.c failalloc.c

CFLAGS+=	-I${.CURDIR:H}
CFLAGS.sysconf_oom_unit.c+=	-I${SRCTOP}/contrib/libucl/include

LIBADD+=	otelexport
LIBADD.sysconf_oom_test+=	ucl

.include <bsd.test.mk>
