PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/tzfs

ATF_TESTS_C+=	tzfsd_test
ATF_TESTS_C+=	libtzfsd_protocol_test
ATF_TESTS_C+=	tzfsd_config_test

CFLAGS.tzfsd_test.c+=	-I${SRCTOP}/lib/libtzfsd
CFLAGS.tzfsd_test.c+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.tzfsd_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.tzfsd_test.c+=	-I${SRCTOP}/sys
LIBADD.tzfsd_test+=	tzfsd trustedzfs
LDFLAGS.tzfsd_test+=	-Wl,-rpath,${OBJTOP}/lib/libtzfsd
CFLAGS.libtzfsd_protocol_test.c+=	-I${SRCTOP}/lib/libtzfsd
CFLAGS.libtzfsd_protocol_test.c+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.libtzfsd_protocol_test.c+=	-I${SRCTOP}/lib/libtrustedzfs
CFLAGS.libtzfsd_protocol_test.c+=	-I${SRCTOP}/sys
LIBADD.libtzfsd_protocol_test+=	tzfsd trustedzfs
LDFLAGS.libtzfsd_protocol_test+=	-Wl,-rpath,${OBJTOP}/lib/libtzfsd
SRCS.tzfsd_config_test=	tzfsd_config_test.c config.c
CFLAGS.tzfsd_config_test+=	-I${SRCTOP}/usr.sbin/tzfsd
CFLAGS.tzfsd_config_test+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.tzfsd_config_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.tzfsd_config_test+=	ucl
.PATH:	${SRCTOP}/usr.sbin/tzfsd

BINDIR=		${TESTSDIR}

.include <bsd.test.mk>
