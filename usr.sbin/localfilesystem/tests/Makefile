PACKAGE=	localfilesystem-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/localfilesystem

CFLAGS+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libfilesystemcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	scratch_test
SRCS.scratch_test=	scratch_test.c scratch.c

ATF_TESTS_C+=	disk_test
SRCS.disk_test=	disk_test.c disk.c

ATF_TESTS_C+=	store_test
SRCS.store_test=	store_test.c disk.c scratch.c store.c

ATF_TESTS_C+=	provider_test
SRCS.provider_test=	provider_test.c filesystemcmp.c disk.c scratch.c store.c
CFLAGS.provider_test+=	-DFILESYSTEMCMP_TESTING
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libauditcmp
CFLAGS.provider_test+=	-I${SRCTOP}/lib/libchannel
CFLAGS.provider_test+=	-I${SRCTOP}/sys
LIBADD.provider_test=	auditcmp channel filesystemcmp service
NO_SHARED.provider_test=	yes
.PATH:		${.CURDIR}/..

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@MK_DTRACE@,${MK_DTRACE},g'

.include <bsd.test.mk>
