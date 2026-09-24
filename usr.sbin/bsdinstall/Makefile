.include <src.opts.mk>

SUBDIR=	distextract distfetch include partedit runconsoles scripts
SUBDIR_PARALLEL=
SUBDIR_DEPEND_distextract = include
SUBDIR_DEPEND_distfetch = include
SUBDIR_DEPEND_partedit = include
SCRIPTS= bsdinstall
MAN= bsdinstall.8
PACKAGE=	bsdinstall
HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

SCRIPTS+=	startbsdinstall
SCRIPTSDIR_startbsdinstall=	${LIBEXECDIR}/bsdinstall

UPDATE_DEPENDFILE= no

FILESDIR=	${SHAREDIR}/bsdinstall
FILES=		5BSD-base.conf

5BSD-base.conf: ${SRCTOP}/usr.sbin/pkg/5BSD.conf.in
	cp ${.ALLSRC} ${.TARGET}
CLEANFILES+=	5BSD-base.conf

.include <bsd.prog.mk>
