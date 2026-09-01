PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/tzfs

# TODO(socket-free): tzfsd_test and libtzfsd_protocol_test drove tzfsd over its
# old UNIX socket (standalone spawn + socket protocol).  tzfsd is now a
# socket-free service_provider (system.Storage over mac_capability channels), so
# both need a fake-service harness (cf. lib/libcryptocmp/tests/fake_service.c)
# that supplies a provider control channel + client session.  Re-enable once
# that harness lands; live coverage meanwhile is the clean-VM boot.
ATF_TESTS_C+=	tzfsd_config_test

SRCS.tzfsd_config_test=	tzfsd_config_test.c config.c
CFLAGS.tzfsd_config_test+=	-I${SRCTOP}/usr.sbin/tzfsd
CFLAGS.tzfsd_config_test+=	-I${SRCTOP}/lib/liboraclert
CFLAGS.tzfsd_config_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.tzfsd_config_test+=	ucl
.PATH:	${SRCTOP}/usr.sbin/tzfsd

BINDIR=		${TESTSDIR}

.include <bsd.test.mk>
