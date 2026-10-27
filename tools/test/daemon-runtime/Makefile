PROGS= runtime_init runner_probe anon_mount_test
SRCS.runtime_init= runtime_init.c
SRCS.runner_probe= runner_probe.c
SRCS.anon_mount_test= anon_mount_test.c
LIBADD.anon_mount_test= atf_c trustedzfs
LIBADD.runner_probe= atf_c
MAN=
NO_SHARED= yes
CFLAGS+= -I${SRCTOP}/sys
.include <bsd.progs.mk>
