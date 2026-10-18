PACKAGE=	tests

TESTSDIR=       ${TESTSBASE}/sys/netpfil/pf/ioctl

ATF_TESTS_C += \
	validation

# Replaces the main ruleset and pings over lo0: its own vnet jail per case.
ATF_TESTS_C += features_glue_ioctl
TEST_METADATA.features_glue_ioctl+=	execenv="jail"
TEST_METADATA.features_glue_ioctl+=	execenv_jail_params="vnet allow.raw_sockets"

.include <bsd.test.mk>
