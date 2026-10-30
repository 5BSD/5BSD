.include <src.opts.mk>

PACKAGE=	libotelexport-tests

ATF_TESTS_C=	otelexport_test
SRCS.otelexport_test=	otelexport_test.c otlp_validate.c otel_testutil.c

# The independent OTLP JSON validator, also used by the bsdinstruments
# and dtrace tests to check exported files.
PROGS=		otlp_validate otlp_collector
SRCS.otlp_validate=	otlp_validate.c otlp_validate_main.c
BINDIR.otlp_validate=	${TESTSDIR}
MAN.otlp_validate=

# A loopback OTLP/HTTP collector for the shell tests.
SRCS.otlp_collector=	otlp_collector_main.c otel_testutil.c
BINDIR.otlp_collector=	${TESTSDIR}
MAN.otlp_collector=
LIBADD.otlp_collector+=	z ssl crypto pthread

# The golden files keep their golden/ subdirectory when installed (the
# package FILES group always installs into TESTSDIR itself).
FILESGROUPS+=	GOLDEN
GOLDEN=		golden/otlpjson-basic.jsonl \
		golden/otlpjson-spans.jsonl \
		golden/otlpjson-semconv.jsonl \
		golden/otlpjson-native.jsonl
GOLDENDIR=	${TESTSDIR}/golden
GOLDENPACKAGE=	${PACKAGE}

# otel.conf(5) system configuration layer.
ATF_TESTS_C+=	sysconf_test
# Allocation-failure sweep over the library as built (failalloc.c
# wraps the allocators of the statically linked objects).
ATF_TESTS_C+=	sysconf_oom_test
SRCS.sysconf_oom_test=	sysconf_oom_test.c failalloc.c

CFLAGS+=	-I${.CURDIR:H}

# Allocation-failure injection (otel_testutil.c).
WRAP_ALLOC=	-Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc \
		-Wl,--wrap=strdup -Wl,--wrap=strndup
LDFLAGS.otelexport_test+=	${WRAP_ALLOC}
LDFLAGS.otlp_collector+=	${WRAP_ALLOC}
LDFLAGS.sysconf_oom_test+=	${WRAP_ALLOC} -Wl,--wrap=reallocarray

LIBADD.otelexport_test+=	otelexport z ssl crypto pthread ucl
LIBADD.sysconf_test+=		otelexport
LIBADD.sysconf_oom_test+=	otelexport ucl

.include <bsd.test.mk>
