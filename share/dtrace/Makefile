#
# Hand installing our scripts and optionally (based on MK_CDDL) installing
# the DTraceToolkit.
#

.include <src.opts.mk>

PACKAGE=	dtrace
SCRIPTS=	blued-att \
		blued-connections \
		blocking \
		mac_capability-audit \
		capsicum-changes \
		capsicum-denials \
		capsicum-xfer \
		mac_capability-calls \
		mac_capability-delegation \
		mac_capability-denials \
		mac_capability-errors \
		mac_capability-fds \
		mac_capability-holders \
		mac_capability-messages \
		mac_capability-nonces \
		mac_capability-services \
		mac_capability-shield \
		mac_capability-summary \
		mac_capability-who \
		procdesc-lifecycle \
		disklatency \
		disklatencycmd \
		hotopen \
		nfsattrstats \
		nfsclienttime \
		oracled-bootstrap \
		oracled-claims \
		oracled-control \
		oracled-errors \
		oracled-ipc \
		oracled-latency \
		oracled-lifecycle \
		oracled-minting \
		serviced-capabilities \
		serviced-connections \
		serviced-exec-latency \
		serviced-ipc \
		serviced-latency \
		serviced-lifecycle \
		serviced-naming \
		serviced-resources \
		serviced-shutdown \
		serviced-timeouts \
		siftr \
		tcpconn \
		tcpdebug \
		tcpstate \
		tcptrack \
		udptrack

SCRIPTSDIR= ${SHAREDIR}/dtrace

DSRCS=		mbuf.d ipfw.d

FILES=		${DSRCS}
FILESDIR=	/usr/lib/dtrace
FILESMODE=	${NOBINMODE}

.include <bsd.prog.mk>
