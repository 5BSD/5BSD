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

${PACKAGE}FILES+=	golden/otlpjson-basic.jsonl
${PACKAGE}FILES+=	golden/otlpjson-spans.jsonl
${PACKAGE}FILESDIR=	${TESTSDIR}/golden

CFLAGS+=	-I${.CURDIR:H}

# Allocation-failure injection (otel_testutil.c).
WRAP_ALLOC=	-Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc \
		-Wl,--wrap=strdup -Wl,--wrap=strndup
LDFLAGS.otelexport_test+=	${WRAP_ALLOC}
LDFLAGS.otlp_collector+=	${WRAP_ALLOC}

LIBADD.otelexport_test+=	otelexport z ssl crypto pthread

.include <bsd.test.mk>
