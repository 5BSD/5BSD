/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otlp_validate — validate OTLP JSON Lines files (one Export*Service
 * Request per line) with the independent validator, optionally
 * comparing them line by line against a golden file.
 *
 * usage: otlp_validate [-g golden.jsonl] [-n] file ...
 *
 * Prints "requests=N logs=N metrics=N datapoints=N spans=N" for the
 * whole input and exits 1 on the first violation or mismatch.  -n
 * skips the line-count check against the golden file's line count
 * for inputs that are a prefix of it.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "otlp_validate.h"

static char **
read_lines(const char *path, size_t *np)
{
	FILE *fp;
	char *line, **lines;
	size_t cap, n;
	ssize_t len;

	if (strcmp(path, "-") == 0)
		fp = stdin;
	else if ((fp = fopen(path, "r")) == NULL)
		err(2, "%s", path);
	lines = NULL;
	n = 0;
	for (;;) {
		line = NULL;
		cap = 0;
		len = getline(&line, &cap, fp);
		if (len < 0) {
			free(line);
			break;
		}
		if (len == 0 || line[len - 1] != '\n')
			errx(1, "%s:%zu: line is not newline-terminated",
			    path, n + 1);
		line[len - 1] = '\0';
		lines = reallocf(lines, (n + 1) * sizeof(*lines));
		if (lines == NULL)
			err(2, "malloc");
		lines[n++] = line;
	}
	if (fp != stdin)
		fclose(fp);
	*np = n;
	return (lines);
}

int
main(int argc, char **argv)
{
	struct otlp_counts c;
	struct jv *v, *g;
	char **lines, **glines, errbuf[1024];
	const char *golden;
	size_t n, gn, gi, i;
	int ch, i_arg, prefix;

	golden = NULL;
	prefix = 0;
	while ((ch = getopt(argc, argv, "g:n")) != -1) {
		switch (ch) {
		case 'g':
			golden = optarg;
			break;
		case 'n':
			prefix = 1;
			break;
		default:
			fprintf(stderr, "usage: otlp_validate [-g golden] [-n] "
			    "file ...\n");
			return (2);
		}
	}
	if (optind == argc)
		errx(2, "no input files");
	glines = NULL;
	gn = 0;
	if (golden != NULL)
		glines = read_lines(golden, &gn);
	memset(&c, 0, sizeof(c));
	gi = 0;
	for (i_arg = optind; i_arg < argc; i_arg++) {
		lines = read_lines(argv[i_arg], &n);
		for (i = 0; i < n; i++) {
			v = jv_parse(lines[i], strlen(lines[i]), errbuf,
			    sizeof(errbuf));
			if (v == NULL)
				errx(1, "%s:%zu: %s", argv[i_arg], i + 1,
				    errbuf);
			if (otlp_validate_request(v, &c, errbuf,
			    sizeof(errbuf)) != 0)
				errx(1, "%s:%zu: %s", argv[i_arg], i + 1,
				    errbuf);
			if (glines != NULL) {
				if (gi >= gn)
					errx(1, "%s:%zu: more lines than the "
					    "golden file", argv[i_arg], i + 1);
				g = jv_parse(glines[gi], strlen(glines[gi]),
				    errbuf, sizeof(errbuf));
				if (g == NULL)
					errx(2, "%s:%zu: %s", golden, gi + 1,
					    errbuf);
				if (jv_match(g, v, errbuf,
				    sizeof(errbuf)) != 0)
					errx(1, "%s:%zu: golden mismatch: %s",
					    argv[i_arg], i + 1, errbuf);
				jv_free(g);
				gi++;
			}
			jv_free(v);
			free(lines[i]);
		}
		free(lines);
	}
	if (glines != NULL && !prefix && gi != gn)
		errx(1, "%zu lines, golden file has %zu", gi, gn);
	for (i = 0; i < gn; i++)
		free(glines[i]);
	free(glines);
	printf("requests=%zu logs=%zu metrics=%zu datapoints=%zu "
	    "spans=%zu", c.requests, c.logs, c.metrics, c.datapoints,
	    c.spans);
	/* Experimental profiles, only when there are any. */
	if (c.profiles > 0)
		printf(" profiles=%zu samples=%zu", c.profiles, c.samples);
	printf("\n");
	return (0);
}
