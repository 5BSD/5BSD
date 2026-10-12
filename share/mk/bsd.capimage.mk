# SPDX-License-Identifier: BSD-2-Clause
# Link unsigned policy input in a non-allocated ELF section. Signing happens
# after the final strip/install step; private keys never enter build rules.
.if defined(CAPIMAGE_MANIFEST) && defined(PROG)
.if !defined(SRCS)
.if defined(PROG_CXX)
SRCS= ${PROG}.cc
.else
SRCS= ${PROG}.c
.endif
.endif
.if ${CAPIMAGE_MANIFEST:[#]} != 1
.error CAPIMAGE_MANIFEST must name exactly one manifest or profile document
.endif
.if ${CAPIMAGE_MANIFEST:M/*}
_CAPIMAGE_POLICY= ${CAPIMAGE_MANIFEST}
.else
_CAPIMAGE_POLICY= ${.CURDIR}/${CAPIMAGE_MANIFEST}
.endif
_CAPIMAGE_ASM= ${PROG}.capimage.S
_CAPIMAGE_AWK:= ${.PARSEDIR}/capimage.awk
SRCS+= ${_CAPIMAGE_ASM}
# install -s would remove the non-allocated build input. Prepare a stripped
# install image explicitly, retaining just this section for the final signer.
_CAPIMAGE_INSTALL= ${PROG}.capimage.install
STRIP=
all: ${_CAPIMAGE_INSTALL}
${_CAPIMAGE_INSTALL}: ${PROG}
	${OBJCOPY} --strip-all --keep-section=.5bsd.policy ${PROG} ${.TARGET}
CLEANFILES+= ${_CAPIMAGE_INSTALL}
CLEANFILES+= ${_CAPIMAGE_ASM} ${_CAPIMAGE_ASM}.tmp
${_CAPIMAGE_ASM}: ${_CAPIMAGE_POLICY} ${_CAPIMAGE_AWK}
	LC_ALL=C od -An -v -tu1 ${_CAPIMAGE_POLICY} | \
	    LC_ALL=C awk -f ${_CAPIMAGE_AWK} > ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}
.endif
