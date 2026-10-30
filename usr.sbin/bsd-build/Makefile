.include <src.opts.mk>
PACKAGE= bsd-build
PROG= build-bsd
SRCS= build-bsd.c
LIBADD= md
LINKS= ${BINDIR}/build-bsd ${BINDIR}/bsd-build
MAN= bsd-build.8
MLINKS= bsd-build.8 build-bsd.8
FILESGROUPS+= EXAMPLES
EXAMPLES= bsd-build.conf.sample certificate-policy.json module-policy.json library-policy.json database-output-policy.json root-layout.json
.PATH: ${SRCTOP}/tools/build/capimage
EXAMPLESDIR= ${SHAREDIR}/examples/bsd-build
SUBDIR+= ucl-policy-json capsule-policy-validate
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.prog.mk>
