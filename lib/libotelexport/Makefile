.include <src.opts.mk>

LIB=		otelexport
INTERNALLIB=

SRCS=		oe_util.c \
		oe_id.c \
		oe_sink.c \
		oe_text.c \
		oe_jsonl.c \
		oe_collapsed.c \
		oe_http.c \
		oe_otlpenc.c \
		oe_otlp.c \
		oe_otlpfile.c \
		oe_sysconf.c \
		oe_service.c

INCS=		otelexport.h

MAN=		libotelexport.3 \
		oe_sysconf.3
MLINKS+=	oe_sysconf.3 oe_sysconf_init.3
MLINKS+=	oe_sysconf.3 oe_sysconf_load.3
MLINKS+=	oe_sysconf.3 oe_sysconf_free.3
MLINKS+=	oe_sysconf.3 oe_headers_file_load.3
MLINKS+=	oe_sysconf.3 oe_attrs_free.3
MLINKS+=	oe_sysconf.3 oe_env_load_system.3
MLINKS+=	oe_sysconf.3 oe_service_open.3
MLINKS+=	oe_sysconf.3 oe_service_close.3
MLINKS+=	oe_sysconf.3 oe_service_flush.3
MLINKS+=	oe_sysconf.3 oe_drop_privileges.3
MLINKS+=	libotelexport.3 oe_text_new.3
MLINKS+=	libotelexport.3 oe_jsonl_new.3
MLINKS+=	libotelexport.3 oe_collapsed_new.3
MLINKS+=	libotelexport.3 oe_text_sink_new.3
MLINKS+=	libotelexport.3 oe_jsonl_sink_new.3
MLINKS+=	libotelexport.3 oe_jsonl_resource_new.3
MLINKS+=	libotelexport.3 oe_collapsed_sink_new.3
MLINKS+=	libotelexport.3 oe_otlp_new.3
MLINKS+=	libotelexport.3 oe_otlpjson_new.3
MLINKS+=	libotelexport.3 oe_sink_open.3
MLINKS+=	libotelexport.3 oe_sink_write.3
MLINKS+=	libotelexport.3 oe_sink_poll.3
MLINKS+=	libotelexport.3 oe_sink_flush.3
MLINKS+=	libotelexport.3 oe_sink_stream.3
MLINKS+=	libotelexport.3 oe_sink_path.3
MLINKS+=	libotelexport.3 oe_sink_close.3
MLINKS+=	libotelexport.3 oe_start.3
MLINKS+=	libotelexport.3 oe_event.3
MLINKS+=	libotelexport.3 oe_snapshot.3
MLINKS+=	libotelexport.3 oe_flush.3
MLINKS+=	libotelexport.3 oe_shutdown.3
MLINKS+=	libotelexport.3 oe_exporter_free.3
MLINKS+=	libotelexport.3 oe_report_drops.3
MLINKS+=	libotelexport.3 oe_env_load.3
MLINKS+=	libotelexport.3 oe_env_free.3
MLINKS+=	libotelexport.3 oe_config_load.3
MLINKS+=	libotelexport.3 oe_resource_init.3
MLINKS+=	libotelexport.3 oe_otlp_config_env.3
MLINKS+=	libotelexport.3 oe_severity_text.3
MLINKS+=	libotelexport.3 oe_span.3
MLINKS+=	libotelexport.3 oe_host_detect.3
MLINKS+=	libotelexport.3 oe_host_arch_semconv.3
MLINKS+=	libotelexport.3 oe_resource_host.3
MLINKS+=	libotelexport.3 oe_id_random.3
MLINKS+=	libotelexport.3 oe_id_derive.3
MLINKS+=	libotelexport.3 oe_id_hex.3
MLINKS+=	libotelexport.3 oe_id_is_zero.3
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
MLINKS+=	libotelexport.3 oe_sink_reopen.3
MLINKS+=	libotelexport.3 oe_sink_reopen_request.3
MLINKS+=	libotelexport.3 oe_env_sink_open.3
MLINKS+=	libotelexport.3 oe_exporter_open.3

# oe_sysconf.c reads otel.conf(5) with libucl.
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
LIBADD=		z ssl crypto pthread ucl

WARNS?=		6

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
