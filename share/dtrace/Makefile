#
# Hand installing our scripts and optionally (based on MK_CDDL) installing
# the DTraceToolkit.
#

.include <src.opts.mk>

PACKAGE=	dtrace
SCRIPTS=	blued-att \
		blued-connections \
		blocking \
		cap_rt-audit \
		capsicum-changes \
		cap_rt-calls \
		cap_rt-delegation \
		cap_rt-denials \
		cap_rt-errors \
		cap_rt-fds \
		cap_rt-holders \
		cap_rt-messages \
		cap_rt-nonces \
		cap_rt-services \
		cap_rt-shield \
		cap_rt-summary \
		cap_rt-who \
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
