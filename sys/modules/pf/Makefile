# OpenBSD PF (contrib/openbsd-pf/sys/net) built for 5BSD through the
# compatibility layer in sys/netpfil/openbsd-pf.

.PATH: ${SRCTOP}/contrib/openbsd-pf/sys/net ${SRCTOP}/contrib/openbsd-pf/sys/netinet \
	${SRCTOP}/sys/netpfil/openbsd-pf

KMOD=	pf
SRCS=	pf.c pf_if.c pf_ioctl.c pf_lb.c pf_norm.c pf_osfp.c pf_ruleset.c \
	pf_syncookies.c pf_table.c radix.c inet_nat64.c in4_cksum.c
SRCS+=	if_pflog.c if_pflow.c if_pfsync.c
# 5BSD glue
GLUE=	openbsd_compat.c openbsd_net.c openbsd_ifq.c pf_freebsd.c pf_sdt.c \
	pf_divert.c pf_dummynet.c pf_jail.c pf_sysctl.c
SRCS+=	${GLUE}
CFLAGS.radix.c+=	-DOBSD_RADIX_IMPL
.for f in ${GLUE}
CFLAGS.${f}+=	-DOPENBSD_PF_GLUE
.endfor
SRCS+=	opt_inet.h opt_inet6.h opt_bpf.h opt_global.h

# Native generated-offset helpers must not include the PF compatibility
# header before genoffset.c defines GENOFFSET (a self-dependency on offset.inc).
# Keep wrapper headers before the native sys include directory.
CFLAGS+=	-I${SRCTOP}/sys/netpfil/openbsd-pf/include
.for f in ${SRCS:M*.c}
CFLAGS.${f}+=	-include ${SRCTOP}/sys/netpfil/openbsd-pf/openbsd_compat.h
CFLAGS.${f}+=	-DOPENBSD_PF
.endfor

# OpenBSD code is not written for these 5BSD warning defaults.
CWARNFLAGS+=	-Wno-missing-prototypes -Wno-strict-prototypes -Wno-format \
		-Wno-incompatible-pointer-types-discards-qualifiers \
		-Wno-cast-qual -Wno-unused-but-set-variable \
		-Wno-pointer-sign -Wno-sign-compare -Wno-address-of-packed-member \
		-Wno-constant-conversion

.include <bsd.kmod.mk>
