/* SPDX-License-Identifier: BSD-2-Clause */
/* Bounded libc/libsys smoke checks; the maintained libc suites remain required. */
#include <sys/types.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <errno.h>
#include <locale.h>
#include <netdb.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#define CHECK(test) do { \
	if (!(test)) { \
		fprintf(stderr, "%s:%d: %s (errno=%d)\n", \
		    __FILE__, __LINE__, #test, errno); \
		return (1); \
	} \
} while (0)

static int
compare(const void *left, const void *right)
{
	int a = *(const int *)left, b = *(const int *)right;
	return ((a > b) - (a < b));
}

static int
memory_and_text(void)
{
	int values[] = { 9, -1, 4, 0, 7 }, key = 4, *found;
	char *buffer, *end;
	void *aligned;
	regex_t expression;
	regmatch_t match[2];
	wchar_t wide;
	mbstate_t state = { 0 };

	buffer = calloc(128, 1);
	CHECK(buffer != NULL && buffer[127] == 0);
	memcpy(buffer, "abcdef", 7);
	memmove(buffer + 1, buffer, 7);
	CHECK(strcmp(buffer, "aabcdef") == 0);
	buffer = realloc(buffer, 4096);
	CHECK(buffer != NULL && strcmp(buffer, "aabcdef") == 0);
	free(buffer);
	CHECK(posix_memalign(&aligned, 64, 1024) == 0);
	CHECK((uintptr_t)aligned % 64 == 0);
	memset(aligned, 0xa5, 1024);
	CHECK(((unsigned char *)aligned)[1023] == 0xa5);
	free(aligned);
	qsort(values, 5, sizeof(values[0]), compare);
	CHECK(values[0] == -1 && values[4] == 9);
	found = bsearch(&key, values, 5, sizeof(values[0]), compare);
	CHECK(found != NULL && *found == 4);
	CHECK(strtod("12.5tail", &end) == 12.5 && strcmp(end, "tail") == 0);
	CHECK(strtoll("-123tail", &end, 10) == -123 && strcmp(end, "tail") == 0);
	CHECK(setlocale(LC_ALL, "C") != NULL);
	CHECK(mbrtowc(&wide, "Q", 1, &state) == 1 && wide == L'Q');
	CHECK(regcomp(&expression, "^item-([0-9]+)$", REG_EXTENDED) == 0);
	CHECK(regexec(&expression, "item-123", 2, match, 0) == 0);
	CHECK(match[1].rm_so == 5 && match[1].rm_eo == 8);
	regfree(&expression);
	return (0);
}

static int
streams_and_syscalls(void)
{
	FILE *stream;
	char text[32], token;
	int pagesize, pipefd[2], status;
	void *mapping;
	pid_t child, waited;
	ssize_t count;

	/* Dynamic libc must reach libsys through its auxiliary filter. */
	CHECK(elf_aux_info(AT_PAGESZ, &pagesize, sizeof(pagesize)) == 0);
	CHECK(pagesize > 0 && pagesize == sysconf(_SC_PAGESIZE));
	mapping = mmap(NULL, (size_t)pagesize, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	CHECK(mapping != MAP_FAILED);
	memset(mapping, 0x42, (size_t)pagesize);
	CHECK(mprotect(mapping, (size_t)pagesize, PROT_READ) == 0);
	CHECK(((const unsigned char *)mapping)[pagesize - 1] == 0x42);
	CHECK(munmap(mapping, (size_t)pagesize) == 0);
	stream = tmpfile();
	CHECK(stream != NULL);
	CHECK(fprintf(stream, "%s %d\n", "libc", 42) == 8);
	CHECK(fflush(stream) == 0 && fseek(stream, 0, SEEK_SET) == 0);
	CHECK(fgets(text, sizeof(text), stream) != NULL);
	CHECK(strcmp(text, "libc 42\n") == 0 && fclose(stream) == 0);
	CHECK(pipe(pipefd) == 0);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		close(pipefd[0]);
		count = write(pipefd[1], "X", 1);
		close(pipefd[1]);
		_exit(count == 1 ? 0 : 1);
	}
	close(pipefd[1]);
	do {
		count = read(pipefd[0], &token, 1);
	} while (count == -1 && errno == EINTR);
	close(pipefd[0]);
	do {
		waited = waitpid(child, &status, 0);
	} while (waited == -1 && errno == EINTR);
	CHECK(count == 1 && token == 'X');
	CHECK(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	return (0);
}

int
main(void)
{
	struct addrinfo hints = { 0 }, *result;

	CHECK(memory_and_text() == 0);
	CHECK(streams_and_syscalls() == 0);
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	CHECK(getaddrinfo("127.0.0.1", "80", &hints, &result) == 0);
	CHECK(result != NULL && result->ai_family == AF_INET);
	freeaddrinfo(result);
	return (0);
}
