.PATH:		${SRCTOP}/tests
KYUAFILE=	yes

.include <src.opts.mk>
.if ${MK_OPENSSH} != "no"
.include "${SRCTOP}/secure/ssh.mk"
.PATH: ${SSHDIR}
ATF_TESTS_C+= loginrec_test
SRCS.loginrec_test= loginrec_test.c loginrec.c
LIBADD.loginrec_test= ssh util
.endif
.include <bsd.test.mk>
