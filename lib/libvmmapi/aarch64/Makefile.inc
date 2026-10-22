SRCS+=	vmmapi_machdep.c

# Checkpoint ioctls; a kernel without options BHYVE_SNAPSHOT returns ENOTTY.
CFLAGS+= -DWITH_VMMAPI_SNAPSHOT
