.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	capsulert
SHLIB_MAJOR=	2

MAN=	libcapsulert.3
MLINKS+=	libcapsulert.3 parse_port_range_string.3
MLINKS+=	libcapsulert.3 parse_port_range_obj.3
MLINKS+=	libcapsulert.3 parse_address_string.3
MLINKS+=	libcapsulert.3 parse_net_protocol_string.3
MLINKS+=	libcapsulert.3 parse_bdaddr_string.3
MLINKS+=	libcapsulert.3 parse_jail_action_string.3
MLINKS+=	libcapsulert.3 parse_jail_actions.3
MLINKS+=	libcapsulert.3 parse_file_action_string.3
MLINKS+=	libcapsulert.3 parse_file_actions.3
MLINKS+=	libcapsulert.3 parse_storage_right_string.3
MLINKS+=	libcapsulert.3 parse_storage_rights.3
MLINKS+=	libcapsulert.3 parse_storage_lifetime_string.3
MLINKS+=	libcapsulert.3 ort_net_domain_name.3
MLINKS+=	libcapsulert.3 ort_net_direction_name.3
MLINKS+=	libcapsulert.3 ort_net_protocol_name.3

SRCS=	claim_parse.c
INCS=	capsulert.h claim_parse.h capsule_ctl.h \
	switchboard_ctl.h capsule_svc_proto.h switchboard_svc_proto.h \
	bsdfilesystem_proto.h

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		ucl

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
