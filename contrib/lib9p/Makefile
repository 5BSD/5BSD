# Note: to turn on debug, use -DL9P_DEBUG=L9P_DEBUG,
# and set env variable LIB9P_LOGGING to stderr or to
# the (preferably full path name of) the debug log file.

LIB=		9p
SHLIB_MAJOR=	1
SRCS=		pack.c \
		connection.c \
		request.c log.c \
		hashtable.c \
		genacl.c \
		utils.c \
		rfuncs.c \
		threadpool.c \
		transport/socket.c \
		backend/fs.c

INCS=		lib9p.h
CC=		clang
CFLAGS=		-g -O0 -DL9P_DEBUG=L9P_DEBUG -DWITH_CASPER
LIBADD=		sbuf casper cap_pwd cap_grp
SUBDIR=		example

# The example is linked against the just-built shared library.  Keep that
# artifact ahead of the recursive target even under make -j; otherwise the
# submake can see only lib9p.a and tries to link non-PIC archive objects into
# its PIE executable.
.ORDER:		lib9p.so.1 all_subdir_example

cscope: .PHONY
	cd ${.CURDIR}; cscope -buq $$(find . -name '*.[ch]' -print)

.include <bsd.lib.mk>
