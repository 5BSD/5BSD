.include <src.opts.mk>

# The default login shell is required even in minimal base installations.
PACKAGE= runtime
PROG= zsh
WARNS?= 0
CSTD= gnu17
INSTALLFLAGS= -S

ZSHSRC= ${SRCTOP}/contrib/zsh
GEN= ${.CURDIR}/generated
.PATH: ${ZSHSRC}/Src ${ZSHSRC}/Src/Zle ${ZSHSRC}/Src/Modules ${ZSHSRC}/Src/Builtins
.PATH: ${GEN}/Src ${GEN}/Src/Zle ${GEN}/Src/Modules ${GEN}/Src/Builtins ${ZSHSRC}/Doc

.include "sources.mk"
SRCS+= sigcount.h errcount.h
CFLAGS+= -I. -I${GEN}/Src -I${GEN}/Src/Zle -I${GEN}/Src/Modules -I${GEN}/Src/Builtins
CFLAGS+= -I${ZSHSRC}/Src -I${ZSHSRC}/Src/Zle -I${ZSHSRC}/Src/Modules -I${ZSHSRC}/Src/Builtins
CFLAGS+= -DHAVE_CONFIG_H -DBOOL_DEFINED -DMACHTYPE='"${MACHINE_ARCH}"'
LIBADD= ncursesw m

# Generate signal tables from the target headers without running target code.
signames.c: ${ZSHSRC}/Src/signames1.awk ${ZSHSRC}/Src/signames2.awk \
    ${SRCTOP}/sys/sys/signal.h
	awk -f ${ZSHSRC}/Src/signames1.awk ${SRCTOP}/sys/sys/signal.h > sigtmp.c
	${CC} -E ${CFLAGS} sigtmp.c > sigtmp.out
	awk -f ${ZSHSRC}/Src/signames2.awk sigtmp.out > ${.TARGET}
sigcount.h: signames.c
	grep 'define.*SIGCOUNT' ${.ALLSRC} > ${.TARGET}
CLEANFILES+= signames.c sigcount.h sigtmp.c sigtmp.out

errnames.c: ${ZSHSRC}/Src/Modules/errnames1.awk ${ZSHSRC}/Src/Modules/errnames2.awk \
    ${SRCTOP}/sys/sys/errno.h
	awk -f ${ZSHSRC}/Src/Modules/errnames1.awk ${SRCTOP}/sys/sys/errno.h > errtmp.c
	${CC} -E ${CFLAGS} errtmp.c > errtmp.out
	awk -f ${ZSHSRC}/Src/Modules/errnames2.awk errtmp.out > ${.TARGET}
errcount.h: errnames.c
	grep 'define.*ERRCOUNT' ${.ALLSRC} > ${.TARGET}
CLEANFILES+= errnames.c errcount.h errtmp.c errtmp.out
.NOPATH: signames.c sigcount.h errnames.c errcount.h zshall.1 run-help

MAN= zsh.1 zshall.1 zshbuiltins.1 zshcalsys.1 zshcompctl.1 \
    zshcompsys.1 zshcompwid.1 zshcontrib.1 zshexpn.1 zshmisc.1 \
    zshmodules.1 zshoptions.1 zshparam.1 zshroadmap.1 zshtcpsys.1 \
    zshzftpsys.1 zshzle.1
# Flatten the combined manual before compression.
zshall.1: ${MAN:Nzshall.1:@m@${ZSHSRC}/Doc/${m}@} ${ZSHSRC}/Doc/zshall.1
	ln -sf ${ZSHSRC}/Doc man1
	soelim ${ZSHSRC}/Doc/zshall.1 > ${.TARGET}
CLEANFILES+= zshall.1 man1

.include "functions.mk"
FILESGROUPS= FILES ZSHLICENSE
ZSHLICENSE= ${ZSHSRC}/LICENCE
ZSHLICENSEDIR= ${SHAREDIR}/doc/zsh
# run-help falls back to the installed manuals when no split help is present.
FILES:= ${FILES:N*/run-help} run-help _mdo
run-help: ${ZSHSRC}/Functions/Misc/run-help
	sed 's|@runhelpdir@|${SHAREDIR}/zsh/help|g' ${.ALLSRC} > ${.TARGET}
CLEANFILES+= run-help

CONFGROUPS= ETC ROOT
ETCPACKAGE= runtime
ROOTPACKAGE= runtime
ETCDIRPACKAGE= runtime
ROOTDIRPACKAGE= runtime
ETC= zshrc
ROOT= dot.zprofile dot.zshrc
ROOTDIR= /root
ROOTDIR_MODE= 0750
ROOTNAME_dot.zprofile= .zprofile
ROOTNAME_dot.zshrc= .zshrc
.PATH: ${SRCTOP}/share/skel

.include <bsd.prog.mk>
