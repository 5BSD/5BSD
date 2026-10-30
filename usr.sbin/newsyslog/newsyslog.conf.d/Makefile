.include <src.opts.mk>

PACKAGE=	newsyslog
CONFSDIR=	/etc/newsyslog.conf.d

CONFGROUPS=	CONFS
CONFS=

.if ${MK_LPR} != "no"
CONFGROUPS+=	LP
LP+=		lpr.conf
LPPACKAGE=	lp
LPDIR=		/etc/newsyslog.conf.d
.endif

.if ${MK_OFED} != "no"
CONFS+=		opensm.conf
.endif

# OpenTelemetry file target (otel.conf(5)), with the rc.d services.
CONFGROUPS+=	OTEL
OTEL+=		otel.conf
OTELPACKAGE=	otel
OTELDIR=	/etc/newsyslog.conf.d

.if ${MK_PF} != "no"
CONFGROUPS+=	PF
PF+=		pf.conf
PFPACKAGE=	pf
PFDIR=		/etc/newsyslog.conf.d
.endif

.if ${MK_PPP} != "no"
CONFGROUPS+=	PPP
PPP+=		ppp.conf
PPPPACKAGE=	ppp
PPPDIR=		/etc/newsyslog.conf.d
.endif

.if ${MK_SENDMAIL} != "no"
CONFGROUPS+=		SENDMAIL
SENDMAIL+=		sendmail.conf
SENDMAILPACKAGE=	sendmail
SENDMAILDIR=		/etc/newsyslog.conf.d
.endif

.include <bsd.prog.mk>
