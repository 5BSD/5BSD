/*-
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <dtraced.h>
#include <dtraced_io.h>
#include <dtraced_wire.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define __cleanup(fn) __attribute__((__cleanup__(fn)))

enum {
	CLEAN = 1,
	STAT
};

static const char *program_name;

enum {
	CLEANUP_STATE = 1000,
	HELP_PAGE,
	SHOW_STATS
};

static struct option longopts[] = {
	{ "cleanup-state",     optional_argument,    NULL,      CLEANUP_STATE },
	{ "help"         ,     no_argument      ,    NULL,      HELP_PAGE     },
	{ "show-stats"   ,     optional_argument,    NULL,      SHOW_STATS    },
	{ NULL           ,     0                ,    NULL,      0             }
};

typedef struct handle {
	int sockfd;
} handle_t;

typedef struct name {
	char   **str;
	size_t n_strs;
} names_t;

static void
freenames(names_t *name)
{
	size_t i;

	for (i = 0; i < name->n_strs; i++)
		free(name->str[i]);

	free(name->str);
}

static void
freehdl(handle_t *hdl)
{

	if (hdl->sockfd >= 0)
		close(hdl->sockfd);
}

static int
parse_names(char *str, names_t *names)
{
	size_t num_commas = 0;
	char *c, **strings;
	size_t i = 0;
	int error;

	/* Callers pass a non-NULL optarg or argv[optind] (optind < argc). */
	if (*str == '\0') {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * We expect comma-separated names here. First, we will simply count
	 * them up.
	 */
	for (c = str; *c != '\0'; c++)
		if (*c == ',') {
			if (c == str || c[-1] == ',' || num_commas >= 4095) {
				errno = EINVAL;
				return (-1);
			}
			num_commas++;
		}
	if (c[-1] == ',') {
		errno = EINVAL;
		return (-1);
	}

	strings = calloc(num_commas + 1, sizeof(char *));
	if (strings == NULL)
		return (-1);

	c = str;
	/*
	 * For every comma (+ 1 for the last string or if no commas), terminate
	 * it with a NULL character and strdup it into our array.
	 */
	for (i = 0; i < num_commas + 1; i++) {
		c = strsep(&str, ",");
		if (strnlen(c, 4096) >= 4096) {
			errno = EMSGSIZE;
			goto failed;
		}

		strings[i] = strdup(c);
		if (strings[i] == NULL)
			goto failed;
	}

	*names = (names_t) { .str = strings, .n_strs = num_commas + 1 };
	return (0);
failed:
	error = errno;
	while (i > 0)
		free(strings[--i]);
	free(strings);
	errno = error;
	return (-1);
}

_Static_assert(sizeof(DTRACED_SOCKPATH) <=
    sizeof(((struct sockaddr_un *)0)->sun_path),
    "DTRACED_SOCKPATH must fit in sun_path");

static handle_t
open_dtraced(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	dtd_initmsg_t initmsg = { 0 };
	int sock, error;
	size_t transferred;
	int64_t deadline;

	(void)strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	addr.sun_len = SUN_LEN(&addr);
	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (sock == -1)
		return ((handle_t){ .sockfd = -1 });
	deadline = dtraced_io_deadline_after(2000);
	if (deadline < 0)
		goto fail;
	if (connect(sock, (struct sockaddr *)&addr, addr.sun_len) != 0) {
		if (errno != EINPROGRESS && errno != EALREADY && errno != EINTR)
			goto fail;
		if (dtraced_io_complete_connect(sock, deadline) != 0)
			goto fail;
	}
	if (dtraced_wire_read_init(sock, &initmsg,
	    deadline, &transferred) != 0)
		goto fail;
	if (!dtraced_wire_valid_server_init(&initmsg)) {
		errno = EPROTO;
		goto fail;
	}
	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.protocol_version = DTRACED_PROTOCOL_VERSION;
	initmsg.kind = DTRACED_KIND_CONSUMER;
	initmsg.subs = DTD_SUB_READDATA;
	snprintf(initmsg.ident, sizeof(initmsg.ident), "dtracedctl-%d", getpid());
	if (dtraced_wire_write_init(sock, &initmsg,
	    deadline, &transferred) != 0)
		goto fail;
	return ((handle_t){ .sockfd = sock });
fail:
	error = errno;
	close(sock);
	errno = error;
	return ((handle_t){ .sockfd = -1 });
}

static int
send_request(handle_t *hdl, names_t *n, uint64_t type,
    dtraced_stats_t *stats)
{
	dtraced_hdr_t header = { 0 };
	unsigned char header_wire[DTRACED_MSGHDRSIZE];
	unsigned char ack;
	size_t length, frame_size = DTRACED_MSGHDRSIZE, transferred;
	int64_t deadline;

	/* parse_names() bounds both: at most 4096 names (4095 commas), each
	 * shorter than 4096 bytes. */
	for (size_t i = 0; i < n->n_strs; i++)
		frame_size += 8 + strlen(n->str[i]) + 1;
	header.msg_type = type;
	header.cleanup.num_entries = n->n_strs;
	dtraced_wire_encode_header(header_wire, &header);
	deadline = dtraced_io_deadline_after(10000);
	if (deadline < 0)
		return (-1);
	if (dtraced_io_write_size(hdl->sockfd, frame_size, deadline,
	    &transferred) != 0 ||
	    dtraced_io_transfer(hdl->sockfd, header_wire, sizeof(header_wire), true,
	    deadline, &transferred) != 0)
		goto fail;
	for (size_t i = 0; i < n->n_strs; i++) {
		length = strlen(n->str[i]) + 1;
		if (dtraced_io_write_size(hdl->sockfd, length, deadline,
		    &transferred) != 0 ||
		    dtraced_io_transfer(hdl->sockfd, n->str[i], length, true,
		    deadline, &transferred) != 0)
			goto fail;
	}
	if (dtraced_io_transfer(hdl->sockfd, &ack, 1, false, deadline,
	    &transferred) != 0)
		goto fail;
	if (ack != 1) {
		errno = EPROTO;
		goto fail;
	}
	if (stats != NULL && dtraced_wire_read_stats(hdl->sockfd, stats,
	    deadline, &transferred) != 0)
		goto fail;
	return (0);
fail:
	{
		int error = errno;
		shutdown(hdl->sockfd, SHUT_RDWR);
		errno = error;
		return (-1);
	}
}

static void
print_help(void)
{
	fprintf(stderr, "Usage: %s\n"
	    "\t--cleanup-state  clean state in VM (all if not set).\n"
	    "\t--help           display this help page.\n"
	    "\t--show-stats     show statistics for a VM (all if not set).\n",
	    program_name);
}

int
main(int argc, const char **argv)
{
	int ch;
	__cleanup(freenames) names_t names_to_stat  = { 0, 0 };
	__cleanup(freenames) names_t names_to_clean = { 0, 0 };
	int action = -1;
	__cleanup(freehdl) handle_t hdl = { .sockfd = -1 };

	program_name = argv[0];

	while ((ch = getopt_long(argc,
	    (char *const *)argv, "", longopts, NULL)) != -1) {
		switch (ch) {
		/* No longopts entry sets a flag, so getopt_long() never returns 0. */
		case HELP_PAGE:
			print_help();
			return (EX_OK);

		case CLEANUP_STATE:
			if (action != -1) {
				print_help();
				return (EX_USAGE);
			}

			action = CLEAN;
			if (optarg == NULL)
				break;

			if (parse_names(optarg, &names_to_clean) != 0) {
				fprintf(stderr, "dtracedctl: invalid VM names: %s\n",
				    strerror(errno));
				return (EX_USAGE);
			}
			break;

		case SHOW_STATS:
			if (action != -1) {
				print_help();
				return (EX_USAGE);
			}

			action = STAT;
			if (optarg == NULL)
				break;

			if (parse_names(optarg, &names_to_stat) != 0) {
				fprintf(stderr, "dtracedctl: invalid VM names: %s\n",
				    strerror(errno));
				return (EX_USAGE);
			}
			break;

		default:
			print_help();
			return (EXIT_FAILURE);
		}
	}
	if (optind != argc) {
		names_t *selected = action == CLEAN ? &names_to_clean :
		    &names_to_stat;
		if ((action != CLEAN && action != STAT) ||
		    optind + 1 != argc || selected->n_strs != 0 ||
		    parse_names((char *)argv[optind], selected) != 0) {
			fprintf(stderr, "dtracedctl: invalid VM names\n");
			return (EX_USAGE);
		}
	}

	if (action != CLEAN && action != STAT) {
		print_help();
		return (EX_USAGE);
	}
	hdl = open_dtraced();
	if (hdl.sockfd < 0) {
		fprintf(stderr, "dtracedctl: connection failed: %s\n", strerror(errno));
		return (EX_UNAVAILABLE);
	}

	switch (action) {
	case CLEAN:
		if (send_request(&hdl, &names_to_clean, DTRACED_MSG_CLEANUP,
		    NULL) != 0) {
			fprintf(stderr, "dtracedctl: cleanup failed: %s\n", strerror(errno));
			return (EX_IOERR);
		}
		break;

	case STAT:
		{
			dtraced_stats_t stats = { 0 };
			if (send_request(&hdl, &names_to_stat, DTRACED_MSG_STATS,
			    &stats) != 0) {
				fprintf(stderr, "dtracedctl: statistics failed: %s\n",
				    strerror(errno));
				return (EX_IOERR);
			}
			printf("forwarder channels: %" PRIu64 "\n"
			    "outbound deliveries: %" PRIu64 "\n"
			    "installed deliveries: %" PRIu64 "\n"
			    "revoked deliveries: %" PRIu64 "\n",
			    stats.forwarder_channels, stats.outbound_deliveries,
			    stats.installed_deliveries, stats.revoked_deliveries);
		}
		break;
	}
	/* action is CLEAN or STAT: checked above before connecting. */

	return (EX_OK);
}
