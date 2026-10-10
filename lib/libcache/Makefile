.include <src.opts.mk>
PACKAGE= libcache
LIB= cache
SHLIB_MAJOR= 1
SRCS= bsd_cache.c
INCS= bsd_cache.h
MAN= bsd_cache.3
.for function in open lookup generation put_if_current create put get remove purge set_limits set_pressure get_stats destroy
MLINKS+= bsd_cache.3 bsd_cache_${function}.3
.endfor
CFLAGS+= -I${SRCTOP}/lib/libnotify -I${SRCTOP}/lib/libservice
LIBADD= notify service pthread
STATIC_CFLAGS+= ${PICFLAG}
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.include <bsd.lib.mk>
