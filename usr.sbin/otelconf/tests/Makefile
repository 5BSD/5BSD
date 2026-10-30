PACKAGE=	otel-tests

ATF_TESTS_SH=	otelconf_test
# rc.d scripts (otel_hwstat, otelpfd, otelauditd, otel_dtrace).
ATF_TESTS_SH+=	otel_rc_test
# hwstat(8) and bsdinstruments(8) emitters configured by otel.conf.
ATF_TESTS_SH+=	otel_emitters_test

# Local fake OTLP/HTTP receiver and independent OTLP-JSON validator,
# shared by the otel-tests programs.
PROGS+=		otlp_fake_receiver otlp_json_validate
BINDIR_otlp_fake_receiver=	${TESTSDIR}
BINDIR_otlp_json_validate=	${TESTSDIR}
MAN.otlp_fake_receiver=
MAN.otlp_json_validate=
LIBADD.otlp_fake_receiver=	z
LIBADD.otlp_json_validate=	ucl
CFLAGS.otlp_json_validate.c+=	-I${SRCTOP}/contrib/libucl/include

${PACKAGE}FILES+=	${.CURDIR:H}/otel.conf.defaults
${PACKAGE}FILES+=	otel.conf.sample
CLEANFILES+=		otel.conf.sample

otel.conf.sample: ${.CURDIR:H}/otel.conf
	cp ${.ALLSRC} ${.TARGET}

.include <bsd.test.mk>
