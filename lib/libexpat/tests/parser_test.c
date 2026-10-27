/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdio.h>
#include <string.h>
#include <bsdxml.h>

struct state { int starts, ends, bad; size_t length; char text[32]; };
static void
start(void *arg, const XML_Char *name, const XML_Char **attrs)
{
	struct state *s = arg;
	(void)attrs;
	if (strcmp(name, s->starts == 0 ? "urn:bsd|root" : "urn:bsd|item") != 0)
		s->bad = 1;
	s->starts++;
}
static void
end(void *arg, const XML_Char *name)
{
	struct state *s = arg;
	(void)name;
	s->ends++;
}
static void
characters(void *arg, const XML_Char *text, int length)
{
	struct state *s = arg;
	if (length < 0 || s->length + (size_t)length >= sizeof(s->text)) {
		s->bad = 1;
		return;
	}
	memcpy(s->text + s->length, text, (size_t)length);
	s->length += (size_t)length;
}
#define CHECK(c) do { if (!(c)) { \
	fprintf(stderr, "line %d: %s\n", __LINE__, #c); return (1); \
} } while (0)
int
main(void)
{
	const char document[] = "<!DOCTYPE root [<!ENTITY value 'payload'>]>"
	    "<root xmlns='urn:bsd'><item>&value;</item></root>";
	const char invalid[] = "<root><item></root>";
	struct state state = {0};
	XML_Parser parser = XML_ParserCreateNS(NULL, '|');
	size_t i;

	CHECK(parser != NULL);
	XML_SetUserData(parser, &state);
	XML_SetElementHandler(parser, start, end);
	XML_SetCharacterDataHandler(parser, characters);
	for (i = 0; i < sizeof(document) - 1; i++)
		CHECK(XML_Parse(parser, document + i, 1, i == sizeof(document) - 2) == XML_STATUS_OK);
	CHECK(!state.bad && state.starts == 2 && state.ends == 2);
	CHECK(state.length == 7 && memcmp(state.text, "payload", 7) == 0);
	XML_ParserFree(parser);
	parser = XML_ParserCreate(NULL);
	CHECK(parser != NULL);
	CHECK(XML_Parse(parser, invalid, sizeof(invalid) - 1, 1) == XML_STATUS_ERROR);
	CHECK(XML_GetErrorCode(parser) == XML_ERROR_TAG_MISMATCH);
	XML_ParserFree(parser);
	return (0);
}
