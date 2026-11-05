# SPDX-License-Identifier: BSD-2-Clause
PROGS= ht-sockpair ht-camera ht-audio vsh-connect vsock-pipe srtool dsrtool l2-console
MAN=
.PATH: ${.CURDIR}/src
.for p in ${PROGS}
SRCS.${p}= ${p}.c
.endfor
LIBADD.ht-audio= m
LIBADD.srtool= md
NO_SHARED.srtool= yes
NO_SHARED.dsrtool= yes
NO_SHARED.l2-console= yes
PYTHON?= python3.12

check: all
	SRTOOL=${.OBJDIR}/srtool ${PYTHON} ${.CURDIR}/lib/coverage-test.py
	${PYTHON} ${.CURDIR}/lib/l2-console-test.py ${.OBJDIR}/l2-console

.include <bsd.progs.mk>
