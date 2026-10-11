.include <src.opts.mk>

PACKAGE=	periodic

CONFGROUPS=	CONFS DATA

CONFS=	100.chksetuid \
	110.neggrpperm \
	200.chkmounts \
	300.chkuid0 \
	400.passwdless \
	410.logincheck \
	700.kernelmsg \
	800.loginfail

DATA=		security.functions
DATAMODE=	444
DATAPACKAGE=	periodic

# NB: keep these sorted by MK_* knobs



.if ${MK_PF} != "no"
CONFGROUPS+=	PF
PF+=		520.pfdenied
PFPACKAGE=	pf
.endif

.if ${MK_INETD} != "no" && ${MK_TCP_WRAPPERS} != "no"
CONFGROUPS+=	TCPWRAP
TCPWRAP+=	900.tcpwrap
TCPWRAPPACKAGE=	tcpd
.endif

.include <bsd.prog.mk>
