PACKAGE=	tests

ATF_TESTS_SH=	syslogd_basic_format_test \
		syslogd_forwarded_format_test \
		syslogd_relayed_format_test \
		syslogd_test

# Run in jail with new vnet so we don't need to worry about address conflicts
TEST_METADATA=	execenv="jail" \
		execenv_jail_params="vnet=new" \
		timeout=20

${PACKAGE}FILES=syslogd_format_test_common.sh \
		syslogd_test_common.sh

# ATF shell programs execute from the object directory before installation.
# Keep the shared helpers beside them for reliable object-tree test runs.
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/syslogd_format_test_common.sh: \
    ${.CURDIR}/syslogd_format_test_common.sh
	${CP} ${.ALLSRC} ${.TARGET}

${.OBJDIR}/syslogd_test_common.sh: \
    ${.CURDIR}/syslogd_test_common.sh
	${CP} ${.ALLSRC} ${.TARGET}

all: ${.OBJDIR}/syslogd_format_test_common.sh \
    ${.OBJDIR}/syslogd_test_common.sh
CLEANFILES+=	syslogd_format_test_common.sh syslogd_test_common.sh
.endif

.include <bsd.test.mk>
