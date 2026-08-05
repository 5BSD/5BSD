PACKAGE=	logd-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/logd
NO_SHARED=

CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice
CFLAGS+=	-I${SRCTOP}/lib/libshmring
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include

ATF_TESTS_C+=	config_test
SRCS.config_test=	config_test.c config.c
LIBADD.config_test+=	ucl

ATF_TESTS_C+=	session_test
SRCS.session_test=	session_test.c session.c
LIBADD.session_test+=	logcmp shmring

ATF_TESTS_C+=	store_test
SRCS.store_test=	store_test.c store.c
LIBADD.store_test+=	logcmp md

ATF_TESTS_C+=	storage_test
SRCS.storage_test=	storage_test.c storage.c store.c
LIBADD.storage_test+=	logcmp md service shmring

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c logcmp.c session.c
CFLAGS.provider_test+=	-DLOGCMP_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	channel logcmp service shmring
NO_SHARED.provider_test=	yes
.PATH:	${.CURDIR}/..

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

.include <bsd.test.mk>
