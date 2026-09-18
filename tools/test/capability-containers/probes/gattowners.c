/*
 * gattowners: print blued's persisted runtime GATT artifacts from a directory
 * (the daemon's state store, exposed to the shell through a snapshot/clone):
 *   OWNER <start> <end> <uuid16> <bundle>   one per ownership record (gattown)
 *   SERVICE <handle> <uuid16>               one per persisted service
 *                                           declaration (gattsrv)
 * so a proof can assert which bundle's services blued still holds.
 */
#include <sys/endian.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blued_persist.h"

int
main(int argc, char **argv)
{
	static struct blued_persist_gatt_owner owners[BLUED_PERSIST_MAX_GATTOWN];
	static struct blued_persist_gatt_srv_attr attrs[BLUED_PERSIST_MAX_GATTSRV_ATTRS];
	uint32_t n = 0, i;
	int dirfd;

	if (argc != 2) {
		(void)fprintf(stderr, "usage: gattowners <state-dir>\n");
		return (2);
	}
	dirfd = open(argv[1], O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		perror(argv[1]);
		return (2);
	}
	if (blued_persist_load_records(dirfd, BLUED_PERSIST_GATTOWN_FILE,
	    BLUED_PERSIST_GATTOWN_MAGIC, BLUED_PERSIST_GATTOWN_VERSION,
	    (uint32_t)sizeof(owners[0]), BLUED_PERSIST_MAX_GATTOWN, owners, &n,
	    NULL) == 0)
		for (i = 0; i < n; i++)
			(void)printf("OWNER %04x %04x %04x %.63s\n", owners[i].start,
			    owners[i].end, owners[i].uuid16, owners[i].bundle);
	n = 0;
	if (blued_persist_gattsrv_load(dirfd, attrs, &n) == 0)
		for (i = 0; i < n; i++)
			if (attrs[i].uuid16 == 0x2800 && attrs[i].value_len == 2)
				(void)printf("SERVICE %04x %04x\n", attrs[i].handle,
				    (unsigned)le16dec(attrs[i].value));
	(void)close(dirfd);
	return (0);
}
