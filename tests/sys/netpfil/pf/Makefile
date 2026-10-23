PACKAGE=	tests

TESTSDIR=       ${TESTSBASE}/sys/netpfil/pf
TESTS_SUBDIRS+=	ioctl
TESTS_SUBDIRS+=	openbsd

ATF_TESTS_SH+=	anchor \
		checksum \
		counters \
		debug \
		delay \
		divert-to \
		dup \
		egress \
		ether \
		features_glue \
		features_pools \
		features_rules \
		forward \
		fragmentation_pass \
		fragmentation_no_reassembly \
		get_state \
		icmp \
		icmp6 \
		if_enc \
		limits \
		limiters \
		loginterface \
		killstate \
		macro \
		match \
		max_pkt_rate \
		max_states \
		mbuf \
		modulate \
		names \
		nat \
		nat64 \
		once \
		osfp \
		pass_block \
		pflog \
		pflow \
		pfsync	\
		prio \
		priority \
		proxy \
		rdr \
		route_to \
		rtable \
		rules_counter \
		scrub_pass \
		sctp \
		set_skip \
		set_tos \
		snmp \
		src_track \
		statefile \
		state_import \
		status \
		syncookie \
		stress \
		synproxy \
		table \
		tcp \
		tos \
		transaction \
		unmapped_mbuf

ATF_TESTS_PYTEST+=	frag4.py
ATF_TESTS_PYTEST+=	frag6.py
ATF_TESTS_PYTEST+=	fuzz_packets.py
ATF_TESTS_PYTEST+=	header.py
ATF_TESTS_PYTEST+=	icmp.py
ATF_TESTS_PYTEST+=	igmp.py
ATF_TESTS_PYTEST+=	mld.py
ATF_TESTS_PYTEST+=	nat44.py
ATF_TESTS_PYTEST+=	nat64.py
ATF_TESTS_PYTEST+=	nat66.py
ATF_TESTS_PYTEST+=	return.py
ATF_TESTS_PYTEST+=	sctp.py
ATF_TESTS_PYTEST+=	tcp.py

# Allow tests to run in parallel in their own jails
TEST_METADATA+= execenv="jail"
TEST_METADATA+= execenv_jail_params="vnet allow.raw_sockets allow.read_msgbuf"

# Delay observes global SDT probes and changes the privileged shared pool limit.
TEST_METADATA.delay+= execenv="" execenv_jail_params="" is_exclusive="true"
# Priority observes kernel FBT probes while creating its own VNET fixture.
TEST_METADATA.priority+= execenv="" execenv_jail_params="" is_exclusive="true"
TEST_METADATA.prio+= execenv="" execenv_jail_params="" is_exclusive="true"
TEST_METADATA.state_import+= execenv="" execenv_jail_params="" is_exclusive="true"
TEST_METADATA.statefile+= execenv="" execenv_jail_params="" is_exclusive="true"
TEST_METADATA.transaction+= execenv="" execenv_jail_params="" is_exclusive="true"
# pf pool limits are owned by the host vnet (a vnet jail cannot change them).
TEST_METADATA.limits+= execenv="" execenv_jail_params="" is_exclusive="true"
TEST_METADATA.syncookie+= execenv="" execenv_jail_params="" is_exclusive="true"

${PACKAGE}FILES+=	\
			bsnmpd.conf \
			pfchksum1.in \
			pfchksum2.in \
			pfchksum3.in \
			CVE-2019-5597.py \
			CVE-2019-5598.py \
			daytime_inetd.conf \
			echo_inetd.conf \
			fragcommon.py \
			frag-direction.py \
			mld-group.py \
			tcp-original-ack.py \
			frag-overindex.py \
			frag-overlimit.py \
			frag-overreplace.py \
			frag-overhole.py \
			frag-adjhole.py \
			pfsync_defer.py \
			pft_ether.py \
			pft_read_ipfix.py \
			rdr-srcport.py \
			tftpd_inetd.conf \
			tftpd_proxy_inetd.conf \
			utils.subr \
			utils.py

${PACKAGE}FILESMODE_bsnmpd.conf=		0555
${PACKAGE}FILESMODE_CVE-2019-5597.py=	0555
${PACKAGE}FILESMODE_CVE-2019-5598.py=	0555
${PACKAGE}FILESMODE_fragcommon.py=	0555
${PACKAGE}FILESMODE_frag-overindex.py=	0555
${PACKAGE}FILESMODE_frag-overlimit.py=	0555
${PACKAGE}FILESMODE_frag-overreplace.py=	0555
${PACKAGE}FILESMODE_frag-overhole.py=	0555
${PACKAGE}FILESMODE_frag-adjhole.py=	0555
${PACKAGE}FILESMODE_pfsync_defer.py=	0555
${PACKAGE}FILESMODE_pft_ether.py=	0555
${PACKAGE}FILESMODE_pft_read_ipfix.py=	0555

PROGS+=	delay_pool_limit statusif_transaction state_import_validation
BINDIR=	${TESTSDIR}
MAN.delay_pool_limit=
CFLAGS.delay_pool_limit+= -I${SRCTOP}/sys/netpfil/openbsd-pf/user
CFLAGS.delay_pool_limit+= -I${SRCTOP}/contrib/openbsd-pf/sys
CFLAGS.delay_pool_limit+= -include ${SRCTOP}/sys/netpfil/openbsd-pf/user/openbsd_compat.h

MAN.statusif_transaction=
CFLAGS.statusif_transaction+= -I${SRCTOP}/sys/netpfil/openbsd-pf/user
CFLAGS.statusif_transaction+= -I${SRCTOP}/contrib/openbsd-pf/sys
CFLAGS.statusif_transaction+= -include ${SRCTOP}/sys/netpfil/openbsd-pf/user/openbsd_compat.h

MAN.state_import_validation=
CFLAGS.state_import_validation+= -I${SRCTOP}/sys/netpfil/openbsd-pf/user
CFLAGS.state_import_validation+= -I${SRCTOP}/contrib/openbsd-pf/sys
CFLAGS.state_import_validation+= -include ${SRCTOP}/sys/netpfil/openbsd-pf/user/openbsd_compat.h

# The OpenBSD rulesets the checksum test loads.
.PATH: ${SRCTOP}/contrib/openbsd-pf/regress/sbin/pfctl

.include <bsd.test.mk>
