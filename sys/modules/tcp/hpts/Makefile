.PATH: ${SRCTOP}/sys/netinet

KMOD=   tcphpts
SRCS=   tcp_hpts.c tcp_lro_hpts.c \
	opt_inet.h opt_inet6.h opt_rss.h device_if.h bus_if.h

# BBR and RACK consume the public high-precision timer API.
EXPORT_SYMS=	YES

.include <bsd.kmod.mk>
