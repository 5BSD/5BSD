/*-
 * Copyright (c) 2014 Pedro Souza <pedrosouza@freebsd.org>
 * All rights reserved.
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
 *
 */

#include "lstd.h"
#include "math.h"
#ifdef LOADER_VERITY_SUPPORT
#include "bootstrap.h"
#endif

#ifdef LOADER_VERIEXEC
#include <verify_file.h>
#endif

FILE *
fopen(const char *filename, const char *mode)
{
	struct stat	st;
	int		fd, m, o;
	int		verified_source __unused = 0;
	FILE		*f;

	if (mode == NULL)
		return NULL;

	switch (*mode++) {
	case 'r':	/* open for reading */
		m = O_RDONLY;
		o = 0;
		break;

	case 'w':	/* open for writing */
		m = O_WRONLY;
		/* These are not actually implemented yet */
		o = O_CREAT | O_TRUNC;
		break;

	default:	/* illegal mode */
		return (NULL);
	}

	if (*mode == '+')
		m = O_RDWR;

	fd = open(filename, m | o);
	if (fd < 0)
		return NULL;

	f = calloc(1, sizeof(FILE));
	if (f == NULL) {
		close(fd);
		return NULL;
	}

	if (fstat(fd, &st) != 0) {
		free(f);
		close(fd);
		return (NULL);
	}

#ifdef LOADER_VERITY_SUPPORT
	if (!(m & O_WRONLY)) {
		int error = verity_check_source(fd);

		if (error != 0) {
			free(f);
			close(fd);
			errno = error;
			return (NULL);
		}
		verified_source = verity_source_verified(fd);
	}
#endif
#ifdef LOADER_VERIEXEC
	/* Mandatory input verification must not be bypassed by object type. */
	if (verify_required() && !(m & O_WRONLY) && !S_ISREG(st.st_mode)) {
		free(f);
		close(fd);
		errno = EAUTH;
		return (NULL);
	}
	/* only regular files and only reading makes sense */
	if (S_ISREG(st.st_mode) && !(m & O_WRONLY) && !verified_source) {
		if (verify_required()) {
			int error;

			/* vectx retains the path until close; Lua may release its string. */
			f->verification_path = strdup(filename);
			if (f->verification_path == NULL) {
				free(f);
				close(fd);
				return (NULL);
			}
			f->verification = vectx_open(fd, f->verification_path,
			    VE_MUST, 0, &st, &error, __func__);
			/* This stdio wrapper has no seek API. Make the restriction
			 * explicit so sequential Lua input needs no replay table. */
			if (f->verification != NULL && error == 0)
				error = vectx_set_sequential(f->verification);
			if (f->verification == NULL || error != 0) {
				vectx_discard(f->verification);
				free(f->verification_path);
				free(f);
				close(fd);
				return (NULL);
			}
		} else if (verify_file(fd, filename, 0, VE_GUESS, __func__) < 0) {
			free(f);
			close(fd);
			return (NULL);
		}
	}
#endif

	f->fd = fd;
	f->offset = 0;
	f->size = st.st_size;
	f->error = 0;

	return (f);
}


FILE *
freopen(const char *filename, const char *mode, FILE *stream)
{
	fclose(stream);
	return (fopen(filename, mode));
}

size_t
fread(void *ptr, size_t size, size_t count, FILE *stream)
{
	size_t bytes;
	ssize_t r;

	if (stream == NULL || stream->error != 0 || size == 0 || count == 0)
		return (0);
	if (ptr == NULL) {
		errno = stream->error = EINVAL;
		return (0);
	}
	if (count > SIZE_MAX / size || (bytes = size * count) > SSIZE_MAX ||
	    bytes > SIZE_MAX - stream->offset) {
		errno = stream->error = EOVERFLOW;
		return (0);
	}
#ifdef LOADER_VERIEXEC
	if (stream->verification != NULL)
		r = vectx_read(stream->verification, ptr, bytes);
	else
#endif
		r = read(stream->fd, ptr, bytes);
	if (r < 0) {
		stream->error = errno != 0 ? errno : EIO;
		return (0);
	}
	stream->offset += (size_t)r;
	/* This loader wrapper historically returns bytes, not element count. */
	return ((size_t)r);
}
size_t
fwrite(const void *ptr, size_t size, size_t count, FILE *stream)
{
	ssize_t w;

	if (stream == NULL || ptr == NULL)
		return (0);
	w = write(stream->fd, ptr, size * count);
	if (w == -1)
		return (0);

	stream->offset += w;
	return ((size_t)w);
}

int
fclose(FILE *stream)
{
	if (stream == NULL)
		return EOF;
#ifdef LOADER_VERIEXEC
	/* luaL_loadfile closes before exposing the compiled script for execution. */
	if (stream->verification != NULL &&
	    vectx_close(stream->verification, __func__) != 0)
		panic("Secure Boot: Lua input verification failed: %s",
		    stream->verification_path);
#endif
	close(stream->fd);
	free(stream->verification_path);
	free(stream);

	return (0);
}

int
ferror(FILE *stream)
{

	return (stream == NULL || stream->fd < 0 || stream->error != 0);
}

int
feof(FILE *stream)
{

	if (stream == NULL)
		return 1;

	return (stream->offset >= stream->size);
}

int
getc(FILE *stream)
{
	unsigned char ch;

	if (fread(&ch, 1, 1, stream) != 1)
		return (EOF);
	return (ch);
}
DIR *
opendir(const char *name)
{
	DIR *dp;
	int fd;

	fd = open(name, O_RDONLY);
	if (fd < 0)
		return NULL;
	dp = fdopendir(fd);
	if (dp == NULL)
		close(fd);
	return dp;
}

DIR *
fdopendir(int fd)
{
	DIR *dp;

	dp = malloc(sizeof(*dp));
	if (dp == NULL)
		return NULL;
	dp->fd = fd;
	return dp;
}

int
closedir(DIR *dp)
{
	close(dp->fd);
	dp->fd = -1;
	free(dp);
	return 0;
}

void
luai_writestring(const char *s, int i)
{

	while (i-- > 0)
		putchar(*s++);
}

/*
 * These routines from here on down are to implement the lua math
 * library, but that's not presently included by default. They are
 * little more than placeholders to allow compilation due to linkage
 * issues with upstream Lua.
 */

int64_t
lstd_pow(int64_t x, int64_t y)
{
	int64_t rv = 1;

	if (y < 0)
		return 0;
	rv = x;
	while (--y)
		rv *= x;

	return rv;
}

int64_t
lstd_floor(int64_t x)
{

	return (x);
}

int64_t
lstd_fmod(int64_t a, int64_t b)
{

	return (a % b);
}

/*
 * This can't be implemented, so maybe it should just abort.
 */
int64_t
lstd_frexp(int64_t a, int *y)
{
	*y = 0;

	return 0;
}
