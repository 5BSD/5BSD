PACKAGE=	netmapd-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/netmapd

ATF_TESTS_C+=	netmapd_policy_test
SRCS.netmapd_policy_test=	netmapd_policy_test.c netmapd_policy.c
CFLAGS.netmapd_policy_test+=	-I${.CURDIR}/..
CFLAGS.netmapd_policy_test+=	-I${SRCTOP}/lib/libnetworkcmp
.PATH:		${.CURDIR}/..

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

.include <bsd.test.mk>
