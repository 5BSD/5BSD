/* SPDX-License-Identifier: BSD-2-Clause */
/* Bounded, self-contained UCL policy normalization; no authority is assigned. */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ucl.h>

#define POLICY_MAX (1024 * 1024)

int
main(int argc, char **argv __unused)
{
	struct ucl_parser *parser;
	ucl_object_t *object;
	unsigned char *input, *output;
	size_t used = 0;
	ssize_t n;

	if (argc != 1)
		errx(1, "usage: bsd-ucl-json < policy.ucl");
	if (cap_enter() == -1)
		err(1, "cap_enter");
	input = malloc(POLICY_MAX + 1);
	if (input == NULL)
		err(1, "malloc");
	while (used <= POLICY_MAX) {
		n = read(STDIN_FILENO, input + used, POLICY_MAX + 1 - used);
		if (n == -1 && errno == EINTR)
			continue;
		if (n == -1)
			err(1, "read policy");
		if (n == 0)
			break;
		used += n;
	}
	if (used > POLICY_MAX || memchr(input, 0, used) != NULL)
		errx(1, "policy exceeds limit or contains NUL");
	parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS |
	    UCL_PARSER_NO_IMPLICIT_ARRAYS | UCL_PARSER_REJECT_MACRO);
	if (parser == NULL)
		err(1, "ucl_parser_new");
	if (!ucl_parser_add_chunk_full(parser, input, used, 0,
	    UCL_DUPLICATE_ERROR, UCL_PARSE_UCL))
		errx(1, "policy parse: %s", ucl_parser_get_error(parser));
	object = ucl_parser_get_object(parser);
	if (object == NULL || ucl_object_type(object) != UCL_OBJECT)
		errx(1, "policy must be an object");
	output = ucl_object_emit(object, UCL_EMIT_JSON_COMPACT);
	if (output == NULL)
		errx(1, "cannot emit policy");
	if (puts((const char *)output) == EOF || fflush(stdout) == EOF)
		err(1, "write policy");
	free(output);
	ucl_object_unref(object);
	ucl_parser_free(parser);
	free(input);
	return (0);
}
