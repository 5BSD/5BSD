/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* These BSD extensions have no public-header declarations; see zopen(3). */
FILE *zopen(const char *, const char *);
FILE *zdopen(int, const char *);
#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d: %s (errno %d)\n", \
		    __FILE__, __LINE__, #condition, errno); \
		return (1); \
	} \
} while (0)

int
main(void)
{
	char path[] = "zopen-test.XXXXXX";
	const char text[] = "BSD zlib stdio wrapper\n";
	char buffer[sizeof(text)];
	FILE *stream;
	int fd;

	fd = mkstemp(path);
	CHECK(fd >= 0);
	CHECK(close(fd) == 0);
	stream = zopen(path, "w");
	CHECK(stream != NULL);
	CHECK(fwrite(text, 1, sizeof(text), stream) == sizeof(text));
	CHECK(fclose(stream) == 0);
	stream = zopen(path, "r");
	CHECK(stream != NULL);
	CHECK(fread(buffer, 1, sizeof(buffer), stream) == sizeof(buffer));
	CHECK(memcmp(buffer, text, sizeof(text)) == 0);
	CHECK(fgetc(stream) == EOF && !ferror(stream));
	rewind(stream);
	CHECK(!ferror(stream));
	CHECK(fread(buffer, 1, sizeof(buffer), stream) == sizeof(buffer));
	CHECK(memcmp(buffer, text, sizeof(text)) == 0);
	CHECK(fclose(stream) == 0);

	fd = open(path, O_WRONLY | O_TRUNC);
	CHECK(fd >= 0);
	stream = zdopen(fd, "w");
	CHECK(stream != NULL);
	CHECK(fwrite(text, 1, sizeof(text), stream) == sizeof(text));
	CHECK(fclose(stream) == 0);
	errno = 0;
	CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
	fd = open(path, O_RDONLY);
	CHECK(fd >= 0);
	stream = zdopen(fd, "r");
	CHECK(stream != NULL);
	CHECK(fread(buffer, 1, sizeof(buffer), stream) == sizeof(buffer));
	CHECK(memcmp(buffer, text, sizeof(text)) == 0);
	CHECK(fclose(stream) == 0);
	errno = 0;
	CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
	CHECK(unlink(path) == 0);
	return (0);
}
