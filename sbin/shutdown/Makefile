PACKAGE=runtime
PROG=	shutdown
MAN=	shutdown.8

# Header-only use of the authorityd control-socket wire protocol
# (authorityd_ctl.h); keeps shutdown a self-contained /sbin binary.
LINKS=	${BINDIR}/shutdown ${BINDIR}/poweroff
MLINKS=	shutdown.8 poweroff.8

BINOWN=	root
BINGRP=	operator
BINMODE=4554

.include <bsd.prog.mk>
