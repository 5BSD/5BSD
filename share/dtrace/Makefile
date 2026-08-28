#
# Hand installing our scripts and optionally (based on MK_CDDL) installing
# the DTraceToolkit.
#

.include <src.opts.mk>

PACKAGE=	dtrace
SCRIPTS=	blued-att \
		blued-connections \
		blued-overview \
		blued-pairing \
		blued-scan \
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
		trustedzfs-handles \
		trustedzfs-denials \
		procdesc-lifecycle \
		disklatency \
		disklatencycmd \
		envfd-events \
		hotopen \
		nfsattrstats \
		nfsclienttime \
		authorityd-bootstrap \
		authorityd-claims \
		authorityd-control \
		authorityd-errors \
		authorityd-ipc \
		authorityd-latency \
		authorityd-lifecycle \
		authorityd-minting \
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
		udptrack \
		vsock-connections \
		vsock-overview \
		vsock-perf \
		vsock-provider \
		vsock-security \
		authwatch \
		privesc \
		capwatch \
		jailwatch \
		tamperwatch \
		rootkit-kld \
		surveil \
		evattr \
		wxwatch \
		inject \
		proctree \
		ipcwatch \
		fdpass \
		netwatch \
		storwatch \
		container-escape \
		persistence \
		fileless-exec \
		cred-theft \
		mac-decisions \
		aio-flow \
		mqueue-flow \
		zfs-admin \
		vmm-passthru \
		rctl-limits \
		daemon-exec \
		casper-mediation \
		pam-stack \
		sessions \
		denials \
		secreport \
		execwatch \
		capflow

SCRIPTSDIR= ${SHAREDIR}/dtrace

DSRCS=		mbuf.d ipfw.d

FILES=		${DSRCS}
FILESDIR=	/usr/lib/dtrace
FILESMODE=	${NOBINMODE}

.include <bsd.prog.mk>
