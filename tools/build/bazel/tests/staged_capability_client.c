/* SPDX-License-Identifier: BSD-2-Clause */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <claim_parse.h>
#include <channel.h>

int
main(void)
{
#ifndef CLIENT_UNUSED
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct channel *channel = NULL;
	uint16_t low, high;
	uint32_t jail;
	uint64_t files, storage;

	if (parse_port_range_string("2048-4096", &low, &high) != 0 ||
	    low != 2048 || high != 4096 ||
	    parse_port_range_string("invalid", &low, &high) == 0)
		return (1);
	/* Execute all three traced parser entry points without privileged work. */
	if (parse_jail_actions(NULL, &jail) != 0 || jail == 0 ||
	    parse_file_actions(NULL, &files) != 0 || files == 0 ||
	    parse_storage_rights(NULL, &storage) != -1 || storage != 0)
		return (2);
	/* API validation only: no endpoint or kernel capability is fabricated. */
	errno = 0;
	if (channel_create(-1, &options, &channel) != -1 || errno != EINVAL)
		return (3);
	errno = 0;
	if (channel_fd(NULL) != -1 || errno != EINVAL)
		return (4);
#endif
	puts("PASS");
	return (0);
}
