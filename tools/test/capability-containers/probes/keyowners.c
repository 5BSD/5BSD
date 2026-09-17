/* keyowners: list the distinct owners holding NAMED keys in the kernel
 * keystore (CIOCGCRYPTOOWNERLIST via libcryptodesc), for the container-model
 * key-reap e2e observer.  Root, outside capability mode. */
#include <sys/cryptodesc.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cryptodesc.h>

int
main(void)
{
	char owners[CRYPTODESC_OWNER_LIST_MAX][CRYPTODESC_KEY_OWNER_MAX];
	uint32_t cursor = 0, count, next, i, total = 0;
	int fd;

	fd = open("/dev/crypto", O_RDWR);
	if (fd == -1) { perror("open /dev/crypto"); return (2); }
	do {
		count = 0; next = 0;
		if (cryptodesc_owner_list(fd, cursor, owners,
		    CRYPTODESC_OWNER_LIST_MAX, &count, &next) != 0) {
			perror("cryptodesc_owner_list"); return (2);
		}
		for (i = 0; i < count; i++) { printf("OWNER=%s\n", owners[i]); total++; }
		cursor = next;
	} while (next != 0);
	printf("OWNERS_TOTAL=%u\n", total);
	return (0);
}
