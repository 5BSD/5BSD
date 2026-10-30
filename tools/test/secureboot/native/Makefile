PROG= native_service_probe
MAN=
NO_SHARED= yes
LIBADD= notify service cryptocmp
CFLAGS+= -I${SRCTOP}/lib/libnotify -I${SRCTOP}/lib/libservice
CFLAGS+= -I${SRCTOP}/lib/libcryptocmp
CFLAGS+= -I${SRCTOP}/sys -I${SRCTOP}/lib/libcapsulert
.include <bsd.prog.mk>
