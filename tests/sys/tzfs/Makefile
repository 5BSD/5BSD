PACKAGE=	tzfs-tests
TESTSDIR=	${TESTSBASE}/sys/tzfs

# TODO(socket-free): bsdfilesystem_test and libbsdfilesystem_protocol_test drove bsdfilesystem over its
# old UNIX socket (standalone spawn + socket protocol).  bsdfilesystem is now a
# socket-free service_provider (system.Storage over mac_capability channels), so
# both need a fake-service harness (cf. lib/libcryptocmp/tests/fake_service.c)
# that supplies a provider control channel + client session.  Re-enable once
# that harness lands; live coverage meanwhile is the clean-VM boot.
ATF_TESTS_C+=	bsdfilesystem_config_test

SRCS.bsdfilesystem_config_test=	bsdfilesystem_config_test.c config.c
CFLAGS.bsdfilesystem_config_test+=	-I${SRCTOP}/usr.sbin/BSDFilesystem
CFLAGS.bsdfilesystem_config_test+=	-I${SRCTOP}/lib/libcapsulert
CFLAGS.bsdfilesystem_config_test+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.bsdfilesystem_config_test+=	ucl
.PATH:	${SRCTOP}/usr.sbin/BSDFilesystem

BINDIR=		${TESTSDIR}

.include <bsd.test.mk>
