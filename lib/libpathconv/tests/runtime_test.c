/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pathconv.h>

int
main(int argc, char **argv)
{
	char *line = NULL;
	size_t capacity = 0;
	unsigned cases = 0, failures = 0;
	FILE *fixture;

	if (argc != 2 || (fixture = fopen(argv[1], "r")) == NULL)
		return (2);
	while (getline(&line, &capacity, fixture) >= 0) {
		char output[4096], *cursor = line, *mode, *path, *base, *expected, *result;
		if (line[0] == '#')
			continue;
		line[strcspn(line, "\r\n")] = '\0';
		mode = strsep(&cursor, "\t");
		path = strsep(&cursor, "\t");
		base = strsep(&cursor, "\t");
		expected = strsep(&cursor, "\t");
		if (!mode || !path || !base || !expected || cursor != NULL)
			return (2);
		if (strcmp(mode, "abs2rel") == 0)
			result = abs2rel(path, base, output, sizeof(output));
		else if (strcmp(mode, "rel2abs") == 0)
			result = rel2abs(path, base, output, sizeof(output));
		else
			return (2);
		cases++;
		if (strcmp(result == NULL ? "ERROR" : result, expected) != 0) {
			fprintf(stderr, "%s(%s, %s): expected %s, got %s\n",
			    mode, path, base, expected, result == NULL ? "ERROR" : result);
			failures++;
		}
	}
	if (ferror(fixture))
		return (2);
	free(line);
	fclose(fixture);
	printf("%u conversion cases, %u failures\n", cases, failures);
	return (cases == 0 || failures != 0);
}
