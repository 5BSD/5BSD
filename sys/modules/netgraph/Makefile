SYSDIR?=${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

SUBDIR=	async \
	${_bluetooth} \
	bpf \
	bridge \
	car \
	checksum \
	cisco \
	deflate \
	device \
	echo \
	eiface \
	etf \
	ether \
	ether_echo \
	gif \
	gif_demux \
	hole \
	hub \
	iface \
	ip_input \
	ksocket \
	l2tp \
	macfilter \
	${_mppc} \
	nat \
	netflow \
	netgraph \
	one2many \
	patch \
	pipe \
	ppp \
	pppoe \
	pred1 \
	socket \
	source \
	split \
	tag \
	tcpmss \
	tee \
	tty \
	UI \
	vjc \
	vlan \
	vlan_rotate

.if ${MK_BLUETOOTH} != "no" || defined(ALL_MODULES)
_bluetooth=	bluetooth
.endif

.if ${MK_CRYPT} != "no" && exists(${SYSDIR}/crypto/rc4/rc4.c)
_mppc=		mppc
.endif

.include <bsd.subdir.mk>
