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

# The OTLP protobuf encoder as a filter, for the oracle tests.
PROGS+=		otlppb_encode
BINDIR.otlppb_encode=	${TESTSDIR}
MAN.otlppb_encode=
LIBADD.otlppb_encode+=	otelexport

# The golden files keep their golden/ subdirectory when installed (the
# package FILES group always installs into TESTSDIR itself).
FILESGROUPS+=	GOLDEN
GOLDEN=		golden/otlpjson-basic.jsonl \
		golden/otlpjson-spans.jsonl \
		golden/otlpjson-semconv.jsonl \
		golden/otlpjson-native.jsonl \
		golden/otlpjson-profiles.jsonl
GOLDENDIR=	${TESTSDIR}/golden
GOLDENPACKAGE=	${PACKAGE}

# otel.conf(5) system configuration layer.
ATF_TESTS_C+=	sysconf_test
# Allocation-failure sweep over the library as built (failalloc.c
# wraps the allocators of the statically linked objects).
ATF_TESTS_C+=	sysconf_oom_test
SRCS.sysconf_oom_test=	sysconf_oom_test.c failalloc.c

CFLAGS+=	-I${.CURDIR:H}

# The OTLP protobuf and gRPC transports: transcoder, decoders, the gRPC
# client against a loopback nghttp2 server (grpc_testsrv.c), OTLP/HTTP
# protobuf against the loopback collector, the exporter end to end.  The
# protobuf the library produces is checked by the C++ oracle (pbcpp).
ATF_TESTS_C+=	otlppb_test
SRCS.otlppb_test=	otlppb_test.c grpc_testsrv.c otel_testutil.c
LDFLAGS.otlppb_test+=	${WRAP_ALLOC}
LIBADD.otlppb_test+=	otelexport nghttp2 z ssl crypto pthread
CFLAGS.grpc_testsrv.c+=	-I${SRCTOP}/contrib/nghttp2/lib/includes \
			-I${SRCTOP}/lib/libnghttp2
SUBDIR+=	pbcpp
ATF_TESTS_SH+=	otlppb_oracle_test

# The experimental profiles signal (dictionary builder, encoder, the
# exporters) and metric exemplars, checked by the C++ oracle and the JSON
# validator.
ATF_TESTS_C+=	otlpprof_test
SRCS.otlpprof_test=	otlpprof_test.c grpc_testsrv.c otel_testutil.c \
			otlp_validate.c
LDFLAGS.otlpprof_test+=	${WRAP_ALLOC}
LIBADD.otlpprof_test+=	otelexport nghttp2 z ssl crypto pthread

# Per-signal endpoints, protocols, headers, timeouts and compression.
ATF_TESTS_C+=	signals_test
SRCS.signals_test=	signals_test.c grpc_testsrv.c otel_testutil.c
LDFLAGS.signals_test+=	${WRAP_ALLOC}
LIBADD.signals_test+=	otelexport nghttp2 z ssl crypto pthread

# Loopback OTLP/HTTP and OTLP/gRPC receiver for the system tests.
PROGS+=		otlp_pb_receiver
SRCS.otlp_pb_receiver=	otlp_pb_receiver.c grpc_testsrv.c otel_testutil.c
BINDIR.otlp_pb_receiver=	${TESTSDIR}
MAN.otlp_pb_receiver=
LDFLAGS.otlp_pb_receiver+=	${WRAP_ALLOC}
LIBADD.otlp_pb_receiver+=	nghttp2 z ssl crypto pthread

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
