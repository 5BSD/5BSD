/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fetch.h>

#define CHECK(c) do { if (!(c)) errx(1, "line %d: %s", __LINE__, #c); } while (0)

int
main(void)
{
	const char *tmp = getenv("TEST_TMPDIR");
	char path[4096], uri[4110], buffer[64];
	const char payload[] = "native libfetch\n\000binary\377";
	struct url *url;
	struct url_stat st;
	FILE *file;
	int fd;

	CHECK(tmp != NULL);
	CHECK(snprintf(path, sizeof(path), "%s/fetch.XXXXXX", tmp) < (int)sizeof(path));
	fd = mkstemp(path);
	CHECK(fd >= 0);
	CHECK(write(fd, payload, sizeof(payload)) == sizeof(payload));
	CHECK(close(fd) == 0);
	CHECK(snprintf(uri, sizeof(uri), "file://%s", path) < (int)sizeof(uri));
	url = fetchParseURL("https://guest:secret@example.test:8443/path?q=1");
	CHECK(url != NULL);
	CHECK(strcmp(url->scheme, "https") == 0);
	CHECK(strcmp(url->host, "example.test") == 0 && url->port == 8443);
	CHECK(strcmp(url->user, "guest") == 0 && strcmp(url->pwd, "secret") == 0);
	CHECK(strcmp(url->doc, "/path?q=1") == 0);
	fetchFreeURL(url);
	CHECK(fetchStatURL(uri, &st, "") == 0 && st.size == sizeof(payload));
	file = fetchGetURL(uri, "");
	CHECK(file != NULL);
	CHECK(fread(buffer, 1, sizeof(buffer), file) == sizeof(payload));
	CHECK(memcmp(buffer, payload, sizeof(payload)) == 0);
	CHECK(feof(file) && !ferror(file));
	CHECK(fclose(file) == 0);
	url = fetchParseURL(uri);
	CHECK(url != NULL);
	url->offset = 7;
	file = fetchGet(url, "");
	CHECK(file != NULL);
	CHECK(fread(buffer, 1, sizeof(buffer), file) == sizeof(payload) - 7);
	CHECK(memcmp(buffer, payload + 7, sizeof(payload) - 7) == 0);
	CHECK(fclose(file) == 0);
	fetchFreeURL(url);
	CHECK(unlink(path) == 0);
	CHECK(fetchGetURL(uri, "") == NULL);
	CHECK(fetchLastErrCode == FETCH_UNAVAIL);
	puts("URL parsing, binary file/stat/offset reads, and missing-file error passed");
	return (0);
}
