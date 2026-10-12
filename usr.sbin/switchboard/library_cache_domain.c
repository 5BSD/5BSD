/* SPDX-License-Identifier: BSD-2-Clause */
/* Explicit issuer-side APIs; possession of a reader/seed grant cannot publish. */
#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/elf_cache_layout.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <capimage.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "library_cache_domain.h"

static int
read_cache(void *argument, uint64_t offset, void *bytes, size_t size)
{
	int fd = *(int *)argument;
	while (size != 0) {
		ssize_t n = pread(fd, bytes, size, offset);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return (n == 0 ? EIO : errno);
		bytes = (char *)bytes + n; size -= n; offset += n;
	}
	return (0);
}

int
svc_cache_domain_create(int issuer, int cache, const char *path,
    const char *sealpath, struct svc_cache_domain *out)
{
	struct cap_cache_prepare prepare = {.backing_fd = -1, .directory_fds = {-1, -1}};
	struct cap_cache_domain_create create;
	struct elf_cache_layout_reader reader;
	struct elf_cache_layout_header *h;
	struct stat st;
	unsigned char buffer[16384], digest[32];
	unsigned digest_size;
	char error[256];
	EVP_MD_CTX *ctx = NULL;
	void *bytes = NULL;
	int layout = -1, seal = -1, backing = -1, domain = -1, result = -1, saved;

	*out = (struct svc_cache_domain){-1, -1};
	prepare.backing_fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_VERIFY);
	prepare.directory_fds[0] = open("/lib", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	prepare.directory_fds[1] = open("/usr/lib", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (prepare.backing_fd < 0 || prepare.directory_fds[0] < 0 || prepare.directory_fds[1] < 0)
		goto out;
	layout = syscall(SYS_cap_process, CAP_CACHE_PREPARE, issuer, 0, &prepare);
	if (layout < 0) goto out;
	seal = open(sealpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (seal < 0 || capimage_check_seal(layout, seal, ELF_CACHE_LAYOUT_DOMAIN,
	    NULL, error, sizeof(error)) < 0) { errno = EAUTH; goto out; }
	if (fstat(layout, &st) != 0) goto out;
	if (st.st_size < (off_t)sizeof(*h) || st.st_size > ELF_CACHE_LAYOUT_MAX_SIZE) {
		errno = EFTYPE; goto out;
	}
	size_t length = st.st_size;
	bytes = malloc(length);
	if (bytes == NULL) goto out;
	int e = read_cache(&layout, 0, bytes, length);
	if (e != 0) { errno = e; goto out; }
	if (fstat(cache, &st) != 0) goto out;
	if (st.st_size < 0 || (uint64_t)st.st_size > ELF_CACHE_MAX_SIZE) { errno = EFTYPE; goto out; }
	reader = (struct elf_cache_layout_reader){read_cache, &cache, st.st_size};
	e = elf_cache_layout_validate(bytes, length, &reader, EM_X86_64, getpagesize());
	if (e != 0) { errno = e; goto out; }
	/* Hash the retained, authenticated, pinned generation, never a reopened path. */
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) { errno = EIO; goto out; }
	for (uint64_t offset = 0; offset < reader.size;) {
		size_t n = reader.size - offset < sizeof(buffer) ? reader.size - offset : sizeof(buffer);
		e = read_cache(&cache, offset, buffer, n);
		if (e != 0 || EVP_DigestUpdate(ctx, buffer, n) != 1) { errno = e != 0 ? e : EIO; goto out; }
		offset += n;
	}
	h = bytes;
	if (EVP_DigestFinal_ex(ctx, digest, &digest_size) != 1 || digest_size != sizeof(digest) ||
	    memcmp(digest, h->cache_sha256, sizeof(digest)) != 0) { errno = EAUTH; goto out; }
	backing = memfd_create("elf-cache-relro", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (backing < 0) goto out;
	create = (struct cap_cache_domain_create){.cache_fd = cache,
	    .layout_fd = layout, .relro_fd = backing};
	domain = syscall(SYS_cap_process, CAP_CACHE_DOMAIN_CREATE, issuer, 0, &create);
	if (domain < 0) goto out;
	*out = (struct svc_cache_domain){domain, backing};
	domain = backing = -1;
	result = 0;
out:
	saved = errno;
	EVP_MD_CTX_free(ctx); free(bytes);
	if (domain >= 0) close(domain);
	if (backing >= 0) close(backing);
	if (layout >= 0) close(layout);
	if (seal >= 0) close(seal);
	if (prepare.backing_fd >= 0) close(prepare.backing_fd);
	for (unsigned i = 0; i < 2; i++)
		if (prepare.directory_fds[i] >= 0) close(prepare.directory_fds[i]);
	errno = saved;
	return (result);
}
int
svc_cache_domain_bind(int issuer, const struct svc_cache_domain *domain,
    int token, bool seed)
{
	struct cap_cache_domain_bind bind = {.token_fd = token,
	    .domain_fd = domain->control_fd, .flags = seed ? CAP_CACHE_DOMAIN_SEED : 0};
	return (syscall(SYS_cap_process, CAP_CACHE_DOMAIN_BIND, issuer, 0, &bind));
}
int
svc_cache_domain_publish(int issuer, const struct svc_cache_domain *domain)
{
	struct cap_cache_domain_publish publish = {.domain_fd = domain->control_fd};
	if (fcntl(domain->backing_fd, F_ADD_SEALS,
	    F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0)
		return (-1);
	return (syscall(SYS_cap_process, CAP_CACHE_DOMAIN_PUBLISH, issuer, 0, &publish));
}
void
svc_cache_domain_close(struct svc_cache_domain *domain)
{
	if (domain->control_fd >= 0) close(domain->control_fd);
	if (domain->backing_fd >= 0) close(domain->backing_fd);
	*domain = (struct svc_cache_domain){-1, -1};
}
