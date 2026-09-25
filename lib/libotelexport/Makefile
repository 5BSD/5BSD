.include <src.opts.mk>

LIB=		otelexport
INTERNALLIB=

SRCS=		oe_util.c \
		oe_text.c \
		oe_jsonl.c \
		oe_collapsed.c \
		oe_http.c \
		oe_otlp.c

INCS=		otelexport.h

MAN=		libotelexport.3
MLINKS+=	libotelexport.3 oe_text_new.3
MLINKS+=	libotelexport.3 oe_jsonl_new.3
MLINKS+=	libotelexport.3 oe_collapsed_new.3
MLINKS+=	libotelexport.3 oe_otlp_new.3
MLINKS+=	libotelexport.3 oe_start.3
MLINKS+=	libotelexport.3 oe_event.3
MLINKS+=	libotelexport.3 oe_snapshot.3
MLINKS+=	libotelexport.3 oe_flush.3
MLINKS+=	libotelexport.3 oe_shutdown.3
MLINKS+=	libotelexport.3 oe_exporter_free.3
MLINKS+=	libotelexport.3 oe_report_drops.3
MLINKS+=	libotelexport.3 oe_env_load.3
MLINKS+=	libotelexport.3 oe_env_free.3
MLINKS+=	libotelexport.3 oe_host_name.3
MLINKS+=	libotelexport.3 oe_host_arch.3
MLINKS+=	libotelexport.3 oe_os_version.3
MLINKS+=	libotelexport.3 oe_buf_init.3
MLINKS+=	libotelexport.3 oe_buf_free.3
MLINKS+=	libotelexport.3 oe_buf_append.3
MLINKS+=	libotelexport.3 oe_buf_appendstr.3
MLINKS+=	libotelexport.3 oe_buf_appendf.3
MLINKS+=	libotelexport.3 oe_buf_appendjson.3
MLINKS+=	libotelexport.3 oe_frame_format.3
MLINKS+=	libotelexport.3 oe_iso8601.3

LIBADD=		z ssl crypto pthread

WARNS?=		6

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
