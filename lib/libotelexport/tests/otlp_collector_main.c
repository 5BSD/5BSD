/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otlp_collector — a loopback OTLP/HTTP collector for shell tests.
 *
 * usage: otlp_collector -o dir [-p port] [-r status,...] [-n count]
 *	      [-t seconds]
 *
 * Listens on 127.0.0.1 (port 0 = any), writes the chosen port to
 * dir/port, and stores request N's URL path in dir/N.path and its
 * (gunzipped) body, newline-terminated, in dir/N.json.  Replies use
 * the -r status list in order, then 200.  Exits after -n requests or
 * -t seconds (default 30), or on SIGTERM.
 */

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "otel_testutil.h"

static volatile sig_atomic_t stop;

static void
on_term(int sig)
{

	(void)sig;
	stop = 1;
}

int
main(int argc, char **argv)
{
	struct coll_reply script[COLL_MAX_SCRIPT];
	struct collector co;
	const char *dir;
	char path[1024], *tok, *list;
	FILE *fp;
	int ch, port, count, secs, nscript, saved, i;

	dir = NULL;
	port = 0;
	count = -1;
	secs = 30;
	nscript = 0;
	memset(script, 0, sizeof(script));
	while ((ch = getopt(argc, argv, "n:o:p:r:t:")) != -1) {
		switch (ch) {
		case 'n':
			count = atoi(optarg);
			break;
		case 'o':
			dir = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'r':
			list = strdup(optarg);
			while ((tok = strsep(&list, ",")) != NULL &&
			    nscript < COLL_MAX_SCRIPT) {
				script[nscript].status = atoi(tok);
				script[nscript].body = "{}";
				nscript++;
			}
			break;
		case 't':
			secs = atoi(optarg);
			break;
		default:
			errx(2, "usage: otlp_collector -o dir [-p port] "
			    "[-r status,...] [-n count] [-t seconds]");
		}
	}
	if (dir == NULL)
		errx(2, "-o dir is required");
	signal(SIGTERM, on_term);
	if (coll_start(&co, port, 0, NULL) != 0)
		err(1, "listen");
	coll_script(&co, script, nscript);
	snprintf(path, sizeof(path), "%s/port", dir);
	if ((fp = fopen(path, "w")) == NULL)
		err(1, "%s", path);
	fprintf(fp, "%d\n", co.port);
	fclose(fp);
	saved = 0;
	for (i = 0; i < secs * 10 && !stop; i++) {
		usleep(100000);
		pthread_mutex_lock(&co.lock);
		for (; saved < co.nreqs; saved++) {
			snprintf(path, sizeof(path), "%s/%d.path", dir,
			    saved + 1);
			fp = fopen(path, "w");
			fprintf(fp, "%s\n", co.reqs[saved].path);
			fclose(fp);
			snprintf(path, sizeof(path), "%s/%d.json", dir,
			    saved + 1);
			fp = fopen(path, "w");
			fwrite(co.reqs[saved].body, 1, co.reqs[saved].bodylen,
			    fp);
			fputc('\n', fp);
			fclose(fp);
		}
		pthread_mutex_unlock(&co.lock);
		if (count >= 0 && saved >= count)
			break;
	}
	coll_stop(&co);
	return (0);
}
