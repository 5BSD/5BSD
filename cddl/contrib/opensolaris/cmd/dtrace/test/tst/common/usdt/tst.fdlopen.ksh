#!/usr/bin/ksh -p
#
# SPDX-License-Identifier: CDDL-1.0
#
# Verify that the drti constructor handles a USDT object loaded by file
# descriptor.  fdlopen(3) supplies no pathname to rtld, so l_name in the
# object's link map may be NULL.  OpenPAM uses this loading path.
#

if [ $# != 1 ]; then
	print -u2 'expected one argument: <dtrace-path>'
	exit 2
fi

dtrace="$1"
if [[ "$dtrace" == */jdtrace ]]; then
	exit 0
fi

startdir="$PWD"
dir=$(mktemp -d -t drtifdlopen.XXXXXX) || exit 2
trap 'cd /; rm -rf "$dir"' EXIT INT TERM
cd "$dir" || exit 2

cat > prov.d <<EOF
provider fdlopen_test {
	probe loaded();
};
EOF

cat > provider.c <<EOF
#include "prov.h"

void
provider_loaded(void)
{
	FDLOPEN_TEST_LOADED();
}
EOF

cat > main.c <<'EOF'
#include <sys/types.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

int
main(void)
{
	void *handle;
	int fd;

	fd = open("./libprovider.so", O_RDONLY);
	if (fd == -1)
		return (1);
	handle = fdlopen(fd, RTLD_NOW | RTLD_LOCAL);
	close(fd);
	if (handle == NULL)
		return (2);
	dlclose(handle);
	return (0);
}
EOF

cat > Makefile <<EOF
all: main libprovider.so

main: main.c
	\$(CC) -o main main.c

prov.h: prov.d
	$dtrace -h -s prov.d

provider.o: provider.c prov.h
	\$(CC) -fPIC -c provider.c

prov.o: prov.d provider.o
	$dtrace -G -s prov.d provider.o

libprovider.so: provider.o prov.o
	\$(CC) -shared -o libprovider.so provider.o prov.o
EOF

if ! make >/dev/null; then
	print -u2 'failed to build fdlopen USDT fixture'
	exit 1
fi

./main
status=$?
cd "$startdir"
exit $status
