.include <src.opts.mk>
PACKAGE= bsd-build
SCRIPTS= bsd-build.sh
SCRIPTSNAME= build-bsd
LINKS= ${BINDIR}/build-bsd ${BINDIR}/bsd-build
MAN= bsd-build.8
MLINKS= bsd-build.8 build-bsd.8
FILESGROUPS+= EXAMPLES BACKENDS
BACKENDS= bsd-make.subr plan-record.py
BACKENDSDIR= ${LIBEXECDIR}/build-bsd
BACKENDSMODE= 0444
EXAMPLES= bsd-build.conf.sample
EXAMPLESDIR= ${SHAREDIR}/examples/bsd-build
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>
