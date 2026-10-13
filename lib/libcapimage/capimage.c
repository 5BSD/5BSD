/* SPDX-License-Identifier: BSD-2-Clause */
/* Bounded ELF note reader and domain-separated Ed25519/SHA-256 signatures.
 * Verification must precede policy parsing. Callers retain/pin the verified
 * vnode before granting authority; a successful check is not a write lock. */
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/mac.h>
#include <sys/stat.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "capimage.h"
#include <sys/capimage_elf.h>

static const unsigned char magic[8] = {'5','B','S','D','S','I','G',0};
static const char image_domain[] = CAPIMAGE_DOMAIN;
struct image_note {
	struct capimage_header header;
	off_t offset;
	off_t file_size;
	bool appended;
};
static int
fail(char *error, size_t size, int code, const char *message)
{
	if (error != NULL && size != 0)
		(void)snprintf(error, size, "%s", message);
	errno = code;
	return (-1);
}
static int
read_at(int fd, void *data, size_t size, off_t offset)
{
	unsigned char *p = data;
	while (size != 0) {
		ssize_t n = pread(fd, p, size, offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			if (n == 0)
				errno = EFTYPE;
			return (-1);
		}
		p += n;
		offset += n;
		size -= (size_t)n;
	}
	return (0);
}
static int
write_at(int fd, const void *data, size_t size, off_t offset)
{
	const unsigned char *p = data;
	while (size != 0) {
		ssize_t n = pwrite(fd, p, size, offset);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			if (n == 0)
				errno = EIO;
			return (-1);
		}
		p += n;
		offset += n;
		size -= (size_t)n;
	}
	return (0);
}
static uint16_t
u16(const void *p, bool little)
{
	return (little ? le16dec(p) : be16dec(p));
}
static uint32_t
u32(const void *p, bool little)
{
	return (little ? le32dec(p) : be32dec(p));
}
static uint64_t
u64(const void *p, bool little)
{
	return (little ? le64dec(p) : be64dec(p));
}
static bool
range(uint64_t offset, uint64_t length, uint64_t size)
{
	return (offset <= size && length <= size - offset);
}
static int
elf_read(void *arg, uint64_t offset, void *data, size_t size)
{
	return (read_at(*(int *)arg, data, size, (off_t)offset));
}
/* Shared structural probe handles signed formats. The remaining reader below
 * validates unsigned build-policy inputs and rejects allocated signature notes. */
static int
find_note(int fd, struct image_note *result, char *error, size_t error_size)
{
	unsigned char eh[sizeof(Elf64_Ehdr)], ph[sizeof(Elf64_Phdr)];
	unsigned char sh[sizeof(Elf64_Shdr)], strings[sizeof(Elf64_Shdr)];
	struct stat st;
	uint64_t limit, phoff, shoff, off, length, stroff, strsize;
	uint16_t count, entsize, shnum, shentsize, strindex;
	bool little, elf64, found = false;
	memset(result, 0, sizeof(*result));
	struct capimage_elf_info info;
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
		return (fail(error, error_size, EFTYPE, "invalid image input"));
	int probe = capimage_elf_probe(elf_read, &fd, st.st_size, &info);
	if (probe < 0)
		return (fail(error, error_size, EFTYPE, "malformed ELF signature locator"));
	if (probe == 1) {
		result->appended = true;
		result->offset = info.descriptor_offset;
		result->file_size = st.st_size;
		if (read_at(fd, &result->header, sizeof(result->header), result->offset) < 0)
			return (-1);
		return (0);
	}

	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
	    st.st_size < (off_t)sizeof(eh) || (uint64_t)st.st_size > CAPIMAGE_FILE_MAX ||
	    read_at(fd, eh, sizeof(eh), 0) < 0)
		return (fail(error, error_size, EFTYPE, "invalid ELF file size/type"));
	if (memcmp(eh, ELFMAG, SELFMAG) != 0 ||
	    (eh[EI_CLASS] != ELFCLASS32 && eh[EI_CLASS] != ELFCLASS64) ||
	    (eh[EI_DATA] != ELFDATA2LSB && eh[EI_DATA] != ELFDATA2MSB) || eh[EI_VERSION] != EV_CURRENT)
		goto malformed;
	little = eh[EI_DATA] == ELFDATA2LSB;
	elf64 = eh[EI_CLASS] == ELFCLASS64;
	limit = (uint64_t)st.st_size;
	if (u16(eh + 16, little) != ET_EXEC && u16(eh + 16, little) != ET_DYN)
		goto malformed;
	phoff = elf64 ? u64(eh + 32, little) : u32(eh + 28, little);
	entsize = u16(eh + (elf64 ? 54 : 42), little);
	count = u16(eh + (elf64 ? 56 : 44), little);
	if (entsize != (elf64 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr)) ||
	    count == 0 || count > 4096 || !range(phoff, (uint64_t)count * entsize, limit))
		goto malformed;
	for (unsigned i = 0; i < count; i++) {
		if (read_at(fd, ph, entsize, (off_t)(phoff + i * entsize)) < 0)
			goto malformed;
		off = elf64 ? u64(ph + 8, little) : u32(ph + 4, little);
		length = elf64 ? u64(ph + 32, little) : u32(ph + 16, little);
		if (length != 0 && !range(off, length, limit))
			goto malformed;
		/* Reject alternate in-segment signature representations so only the
		 * current ELF signature section supplies authenticated policy. */
		if (u32(ph, little) == PT_NOTE) {
			uint64_t end = off + length;
			unsigned notes = 0;
			while (off < end) {
				unsigned char nh[12], owner[5];
				if (++notes > 8192 || !range(off, sizeof(nh), end) ||
				    read_at(fd, nh, sizeof(nh), off) < 0) goto malformed;
				uint64_t namesz = u32(nh, little), descsz = u32(nh + 4, little);
				off += sizeof(nh);
				uint64_t padded = (namesz + 3) & ~UINT64_C(3);
				if (!range(off, padded, end)) goto malformed;
				if (namesz == 5 && u32(nh + 8, little) == CAPIMAGE_NOTE_TYPE) {
					if (read_at(fd, owner, sizeof(owner), off) < 0) goto malformed;
					if (memcmp(owner, "5BSD", sizeof(owner)) == 0)
						return (fail(error, error_size, EFTYPE, "retired inline signature format"));
				}
				off += padded;
				padded = (descsz + 3) & ~UINT64_C(3);
				if (!range(off, padded, end)) goto malformed;
				off += padded;
			}
		}
	}
	result->file_size = st.st_size;
	/* Section tables are unnecessary for verification of a signed image.
	 * Unsigned build inputs use a bounded section-name lookup. */
	shoff = elf64 ? u64(eh + 40, little) : u32(eh + 32, little);
	shentsize = u16(eh + (elf64 ? 58 : 46), little);
	shnum = u16(eh + (elf64 ? 60 : 48), little);
	strindex = u16(eh + (elf64 ? 62 : 50), little);
	if (shoff == 0 && shnum == 0)
		return (fail(error, error_size, ENOENT, "no embedded 5BSD policy"));
	if (shentsize != (elf64 ? sizeof(Elf64_Shdr) : sizeof(Elf32_Shdr)) ||
	    shnum == 0 || shnum > 8192 || strindex == 0 || strindex >= shnum ||
	    !range(shoff, (uint64_t)shnum * shentsize, limit) ||
	    read_at(fd, strings, shentsize, shoff + (uint64_t)strindex * shentsize) < 0 ||
	    u32(strings + 4, little) != SHT_STRTAB)
		goto malformed;
	stroff = elf64 ? u64(strings + 24, little) : u32(strings + 16, little);
	strsize = elf64 ? u64(strings + 32, little) : u32(strings + 20, little);
	if (!range(stroff, strsize, limit)) goto malformed;
	for (unsigned i = 1; i < shnum; i++) {
		char name[sizeof(".5bsd.policy")];
		if (read_at(fd, sh, shentsize, shoff + (uint64_t)i * shentsize) < 0)
			goto malformed;
		uint32_t nameoff = u32(sh, little);
		if (nameoff >= strsize) goto malformed;
		if (!range(nameoff, sizeof(name), strsize)) continue;
		if (read_at(fd, name, sizeof(name), stroff + nameoff) < 0) goto malformed;
		if (memcmp(name, ".5bsd.policy", sizeof(name)) != 0) continue;
		off = elf64 ? u64(sh + 24, little) : u32(sh + 16, little);
		length = elf64 ? u64(sh + 32, little) : u32(sh + 20, little);
		uint64_t flags = elf64 ? u64(sh + 8, little) : u32(sh + 8, little);
		if (found || u32(sh + 4, little) != SHT_PROGBITS || flags != 0 ||
		    length == 0 || length > CAPIMAGE_POLICY_MAX || !range(off, length, limit))
			goto malformed;
		found = true;
		result->offset = (off_t)off; /* raw policy, no signature header */
		result->header.policy_size = htole32((uint32_t)length);
	}
	if (!found) return (fail(error, error_size, ENOENT, "no embedded 5BSD policy"));
	return (0);
malformed:
	return (fail(error, error_size, EFTYPE, "malformed ELF policy container"));
}
/* Hash every file byte, with precisely the signature field replaced by zeros.
 * Including ELF headers, note metadata, signer key, policy and non-loadable
 * bytes prevents header, interpreter, policy and trailing-data substitution. */
static int
hash_fd(int fd, off_t length, off_t zero, size_t zerosize,
    const char *domain, unsigned char digest[32],
    off_t capture_offset, unsigned char *capture, size_t capture_size)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned char buffer[16384];
	off_t off = 0;
	unsigned n;
	int result = -1;
	if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(ctx, domain, strlen(domain) + 1) != 1)
		goto out;
	while (off < length) {
		size_t take = (uint64_t)(length - off) < sizeof(buffer) ?
		    (size_t)(length - off) : sizeof(buffer);
		if (read_at(fd, buffer, take, off) < 0)
			goto out;
		if (capture != NULL && capture_offset < off + (off_t)take &&
		    capture_offset + (off_t)capture_size > off) {
			off_t first = capture_offset > off ? capture_offset : off;
			off_t last = capture_offset + (off_t)capture_size < off + (off_t)take ?
			    capture_offset + (off_t)capture_size : off + (off_t)take;
			memcpy(capture + (first - capture_offset), buffer + (first - off),
			    (size_t)(last - first));
		}
		if (zerosize != 0 && zero < off + (off_t)take &&
		    zero + (off_t)zerosize > off) {
			off_t first = zero > off ? zero : off;
			off_t last = zero + (off_t)zerosize < off + (off_t)take ?
			    zero + (off_t)zerosize : off + (off_t)take;
			memset(buffer + (first - off), 0, (size_t)(last - first));
		}
		if (EVP_DigestUpdate(ctx, buffer, take) != 1)
			goto out;
		off += (off_t)take;
	}
	if (EVP_DigestFinal_ex(ctx, digest, &n) == 1 && n == 32)
		result = 0;
out:
	EVP_MD_CTX_free(ctx);
	return (result);
}
static EVP_PKEY *
read_key(const char *path, bool secret)
{
	FILE *f;
	EVP_PKEY *key;
	if (path == NULL)
		return (NULL);
	f = fopen(path, "r");
	if (f == NULL)
		return (NULL);
	key = secret ? PEM_read_PrivateKey(f, NULL, NULL, NULL) :
	    PEM_read_PUBKEY(f, NULL, NULL, NULL);
	fclose(f);
	if (key != NULL && EVP_PKEY_base_id(key) != EVP_PKEY_ED25519) {
		EVP_PKEY_free(key);
		key = NULL;
	}
	return (key);
}
static int
sign_digest(EVP_PKEY *key, const unsigned char digest[32], unsigned char sig[64])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	size_t size = 64;
	int ok = ctx != NULL && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
	    EVP_DigestSign(ctx, sig, &size, digest, 32) == 1 && size == 64;
	EVP_MD_CTX_free(ctx);
	return (ok ? 0 : -1);
}
static int
verify_digest(const unsigned char key[32], const unsigned char digest[32],
    const unsigned char sig[64])
{
	EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key, 32);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	int ok = pkey != NULL && ctx != NULL &&
	    EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
	    EVP_DigestVerify(ctx, sig, 64, digest, 32) == 1;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return (ok ? 0 : -1);
}
/* Validate each directory component, not only the final key directory. */
static int
trusted_directory(int parent, const char *name)
{
	struct stat st;
	int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &st) < 0 || st.st_uid != 0 || (st.st_mode & 022) != 0) {
		close(fd);
		errno = EPERM;
		return (-1);
	}
	return (fd);
}
static int
system_policy_directory(void)
{
	int etc = trusted_directory(AT_FDCWD, "/etc");
	if (etc < 0)
		return (-1);
	int policy = trusted_directory(etc, "capability"), saved = errno;
	close(etc);
	errno = saved;
	return (policy);
}
int
capimage_signatures_required(bool *required, char *error, size_t error_size)
{
	struct stat st;
	int directory, fd, saved;
	if (required == NULL)
		return (fail(error, error_size, EINVAL, "enforcement result required"));
	*required = false;
	directory = system_policy_directory();
	if (directory < 0) {
		if (errno == ENOENT) return (0);
		return (fail(error, error_size, errno, "invalid signature policy directory"));
	}
	fd = openat(directory, "require-signatures", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	saved = errno; close(directory); errno = saved;
	if (fd < 0) {
		if (errno == ENOENT) return (0);
		return (fail(error, error_size, errno, "cannot read signature enforcement policy"));
	}
	bool valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
	    st.st_uid == 0 && (st.st_mode & 022) == 0;
	close(fd);
	if (!valid)
		return (fail(error, error_size, EPERM, "invalid signature enforcement policy"));
	*required = true;
	return (0);
}
/* A caller-supplied key is for an explicitly selected trust policy. Runtime
 * callers pass NULL and use a root-owned, non-writable system key catalogue.
 * The filename is the raw public key in hex; the file is a PEM public key. */
static int
trusted_key(const unsigned char expected[32], const char *path)
{
	unsigned char actual[32];
	char filename[69];
	size_t size = sizeof(actual);
	EVP_PKEY *key;
	FILE *f;
	struct stat st;
	int dir, fd, result;
	if (path != NULL)
		key = read_key(path, false);
	else {
		int policy = system_policy_directory();
		if (policy < 0)
			return (-1);
		dir = trusted_directory(policy, "keys");
		close(policy);
		if (dir < 0)
			return (-1);
		for (unsigned i = 0; i < 32; i++)
			(void)snprintf(filename + 2 * i, 3, "%02x", expected[i]);
		memcpy(filename + 64, ".pub", 5);
		fd = openat(dir, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		close(dir);
		if (fd < 0)
			return (-1);
		if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
		    (st.st_mode & 022) != 0 || st.st_size > 4096) {
			close(fd);
			return (-1);
		}
		f = fdopen(fd, "r");
		if (f == NULL) {
			close(fd);
			return (-1);
		}
		key = PEM_read_PUBKEY(f, NULL, NULL, NULL);
		fclose(f);
	}
	result = key != NULL && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519 &&
	    EVP_PKEY_get_raw_public_key(key, actual, &size) == 1 && size == 32 &&
	    CRYPTO_memcmp(expected, actual, 32) == 0 ? 0 : -1;
	EVP_PKEY_free(key);
	return (result);
}
static int
verify_image(int fd, const char *keypath, bool require_trust,
    struct capimage_policy *policy, char *error, size_t error_size)
{
	struct image_note note;
	unsigned char digest[32];
	if (policy == NULL)
		return (fail(error, error_size, EINVAL, "policy result is required"));
	memset(policy, 0, sizeof(*policy));
	if (find_note(fd, &note, error, error_size) < 0)
		return (-1);
	if (!note.appended)
		return (fail(error, error_size, ENOATTR, "unsigned build policy"));
	unsigned char present = 0;
	for (size_t i = 0; i < sizeof(note.header.key); i++)
		present |= note.header.key[i];
	for (size_t i = 0; i < sizeof(note.header.signature); i++)
		present |= note.header.signature[i];
	if (present == 0)
		return (fail(error, error_size, ENOATTR, "unsigned manifest note"));
	if (require_trust && trusted_key(note.header.key, keypath) < 0)
		return (fail(error, error_size, EAUTH, "untrusted image signing key"));
	policy->size = le32toh(note.header.policy_size);
	policy->data = malloc(policy->size + 1);
	if (policy->data == NULL)
		return (fail(error, error_size, ENOMEM, "cannot allocate policy"));
	/* Return precisely the policy bytes fed to the authenticated hash, not
	 * a second read that could observe a replacement after verification. */
	if (hash_fd(fd, note.file_size,
	    note.offset + offsetof(struct capimage_header, signature),
	    CAPIMAGE_SIGNATURE_SIZE, image_domain, digest,
	    note.offset + sizeof(note.header), policy->data, policy->size) < 0 ||
	    verify_digest(note.header.key, digest, note.header.signature) < 0) {
		capimage_policy_free(policy);
		return (fail(error, error_size, EAUTH, "invalid image signature"));
	}
	policy->data[policy->size] = '\0';
	memcpy(policy->key, note.header.key, sizeof(policy->key));
	memcpy(policy->digest, digest, sizeof(policy->digest));
	return (0);
}
int
capimage_verify(int fd, const char *keypath, struct capimage_policy *policy,
    char *error, size_t error_size)
{
	return (verify_image(fd, keypath, true, policy, error, error_size));
}
int
capimage_verify_integrity(int fd, struct capimage_policy *policy,
    char *error, size_t error_size)
{
	return (verify_image(fd, NULL, false, policy, error, error_size));
}

void
capimage_policy_free(struct capimage_policy *policy)
{
	if (policy != NULL) {
		free(policy->data);
		memset(policy, 0, sizeof(*policy));
	}
}
int
capimage_sign(int fd, const char *keypath, char *error, size_t error_size)
{
	struct image_note note;
	unsigned char digest[32];
	size_t key_size = 32;
	EVP_PKEY *key;
	int result = -1;
	if (find_note(fd, &note, error, error_size) < 0)
		return (-1);
	if (!note.appended) {
		size_t size = le32toh(note.header.policy_size);
		unsigned char *data = malloc(size);
		if (data == NULL) return (fail(error, error_size, ENOMEM, "policy allocation"));
		int prepared = read_at(fd, data, size, note.offset);
		if (prepared == 0) prepared = capimage_embed(fd, data, size, error, error_size);
		free(data);
		if (prepared < 0 || find_note(fd, &note, error, error_size) < 0) return (-1);
	}
	key = read_key(keypath, true);
	if (key == NULL)
		return (fail(error, error_size, EINVAL, "cannot read Ed25519 private key"));
	memset(note.header.signature, 0, sizeof(note.header.signature));
	if (EVP_PKEY_get_raw_public_key(key, note.header.key, &key_size) == 1 &&
	    key_size == 32 && write_at(fd, &note.header, sizeof(note.header), note.offset) == 0 &&
	    hash_fd(fd, note.file_size, note.offset + offsetof(struct capimage_header, signature),
	    CAPIMAGE_SIGNATURE_SIZE, image_domain, digest, 0, NULL, 0) == 0 &&
	    sign_digest(key, digest, note.header.signature) == 0 &&
	    write_at(fd, &note.header, sizeof(note.header), note.offset) == 0)
		result = 0;
	EVP_PKEY_free(key);
	if (result < 0)
		return (fail(error, error_size, EIO, "cannot sign image"));
	return (0);
}
/* Caller owns a private writable copy; never modify a running image.
 * Existing embedded policy must match exactly, preventing accidental policy
 * replacement across different units. All output is signed after embedding. */
int
capimage_embed(int fd, const void *data, size_t size, char *error, size_t error_size)
{
	struct image_note note;
	struct capimage_header header = {0};
	struct capimage_footer footer = {0};
	struct stat st;
	unsigned char *existing;
	if (data == NULL || size == 0 || size > CAPIMAGE_POLICY_MAX)
		return (fail(error, error_size, EINVAL, "policy size out of bounds"));
	if (find_note(fd, &note, error, error_size) == 0) {
		if (size != le32toh(note.header.policy_size))
			return (fail(error, error_size, EINVAL, "existing embedded policy differs"));
		existing = malloc(size);
		if (existing == NULL)
			return (fail(error, error_size, ENOMEM, "policy allocation"));
		int result = read_at(fd, existing, size, note.offset + (note.appended ? sizeof(note.header) : 0));
		bool same = result == 0 && memcmp(existing, data, size) == 0;
		free(existing);
		if (!same)
			return (fail(error, error_size, EINVAL, "existing embedded policy differs"));
		if (note.appended) return (0);
	} else if (errno != ENOENT)
		return (-1);
	/* All writes are to the caller's private output. Keep the original prefix
	 * intact except for the section table locator in its ELF header. */
	unsigned char eh[64] = {0}, changed[64], sh[64], nh[20] = {0};
	struct capimage_elf_original original = {0};
	if (fstat(fd, &st) < 0 || st.st_size < 64 || read_at(fd, eh, 52, 0) < 0)
		return (fail(error, error_size, EFTYPE, "invalid ELF input"));
	bool elf64 = eh[EI_CLASS] == ELFCLASS64, little = eh[EI_DATA] == ELFDATA2LSB;
	unsigned es = elf64 ? 64 : 52, ss = elf64 ? 64 : 40;
	if (elf64 && read_at(fd, eh + 52, 12, 52) < 0) return (-1);
	uint64_t so = capimage_elf_uint(eh + (elf64 ? 40 : 32), elf64 ? 8 : 4, little);
	unsigned sn = u16(eh + (elf64 ? 60 : 48), little);
	unsigned si = u16(eh + (elf64 ? 62 : 50), little);
	uint64_t old_strings = 0, old_strings_size = sizeof("\0.shstrtab");
	if (sn == 0) {
		if (so != 0 || si != 0) return (fail(error, error_size, EFTYPE, "extended ELF numbering unsupported"));
	} else {
		if (sn >= 8192 || si == 0 || si >= sn ||
		    u16(eh + (elf64 ? 58 : 46), little) != ss ||
		    !range(so, (uint64_t)sn * ss, st.st_size) ||
		    read_at(fd, sh, ss, so + (uint64_t)si * ss) < 0 || u32(sh + 4, little) != SHT_STRTAB)
			return (fail(error, error_size, EFTYPE, "unsupported ELF section table"));
		old_strings = capimage_elf_uint(sh + (elf64 ? 24 : 16), elf64 ? 8 : 4, little);
		old_strings_size = capimage_elf_uint(sh + (elf64 ? 32 : 20), elf64 ? 8 : 4, little);
		if (old_strings_size == 0 || old_strings_size > CAPIMAGE_POLICY_MAX ||
		    !range(old_strings, old_strings_size, st.st_size))
			return (fail(error, error_size, EFTYPE, "invalid ELF string table"));
	}
	uint64_t no = ((uint64_t)st.st_size + 3) & ~UINT64_C(3);
	uint64_t ds = sizeof(header) + size + sizeof(original);
	uint64_t ns = 20 + ((ds + 3) & ~UINT64_C(3));
	uint64_t strings = no + ns, strings_size = old_strings_size + sizeof(CAPIMAGE_ELF_SECTION);
	unsigned new_sn = sn == 0 ? 3 : sn + 1, new_si = sn == 0 ? 1 : si;
	uint64_t table = (strings + strings_size + 7) & ~UINT64_C(7);
	uint64_t end = table + (uint64_t)new_sn * ss;
	if (end + sizeof(footer) > CAPIMAGE_FILE_MAX)
		return (fail(error, error_size, EFBIG, "embedded image exceeds size bound"));
	unsigned char *tail = calloc(1, end + sizeof(footer) - st.st_size);
	if (tail == NULL) return (fail(error, error_size, ENOMEM, "ELF metadata allocation"));
#define TAIL(o) (tail + ((o) - (uint64_t)st.st_size))
	memcpy(header.magic, magic, sizeof(magic));
	header.version = htole32(CAPIMAGE_VERSION);
	header.policy_size = htole32((uint32_t)size);
	memcpy(original.magic, "5BSDORIG", 8);
	original.version = htole32(CAPIMAGE_VERSION);
	original.header_size = htole32(es);
	original.original_size = htole64(st.st_size);
	memcpy(original.original_header, eh, es);
	capimage_elf_put(nh, 5, 4, little);
	capimage_elf_put(nh + 4, ds, 4, little);
	capimage_elf_put(nh + 8, CAPIMAGE_ELF_NOTE_TYPE, 4, little);
	memcpy(nh + 12, "5BSD", 5);
	memcpy(TAIL(no), nh, 20);
	memcpy(TAIL(no + 20), &header, sizeof(header));
	memcpy(TAIL(no + 20 + sizeof(header)), data, size);
	memcpy(TAIL(no + 20 + sizeof(header) + size), &original, sizeof(original));
	if (sn != 0 && (read_at(fd, TAIL(strings), old_strings_size, old_strings) < 0 ||
	    read_at(fd, TAIL(table), (size_t)sn * ss, so) < 0)) { free(tail); return (-1); }
	if (sn == 0) memcpy(TAIL(strings), "\0.shstrtab", sizeof("\0.shstrtab"));
	memcpy(TAIL(strings + old_strings_size), CAPIMAGE_ELF_SECTION, sizeof(CAPIMAGE_ELF_SECTION));
	unsigned char *sp = TAIL(table + (uint64_t)new_si * ss);
	if (sn == 0) {
		capimage_elf_put(sp, 1, 4, little);
		capimage_elf_put(sp + 4, SHT_STRTAB, 4, little);
		capimage_elf_put(sp + (elf64 ? 48 : 32), 1, elf64 ? 8 : 4, little);
	}
	capimage_elf_put(sp + (elf64 ? 24 : 16), strings, elf64 ? 8 : 4, little);
	capimage_elf_put(sp + (elf64 ? 32 : 20), strings_size, elf64 ? 8 : 4, little);
	sp = TAIL(table + (uint64_t)(new_sn - 1) * ss);
	capimage_elf_put(sp, old_strings_size, 4, little);
	capimage_elf_put(sp + 4, SHT_NOTE, 4, little);
	capimage_elf_put(sp + (elf64 ? 24 : 16), no, elf64 ? 8 : 4, little);
	capimage_elf_put(sp + (elf64 ? 32 : 20), ns, elf64 ? 8 : 4, little);
	capimage_elf_put(sp + (elf64 ? 48 : 32), 4, elf64 ? 8 : 4, little);
	memcpy(footer.magic, "5BSDEND", 8);
	footer.version = htole32(CAPIMAGE_VERSION);
	footer.offset = htole64(no + 20); footer.size = htole64(ds);
	memcpy(TAIL(end), &footer, sizeof(footer));
	memcpy(changed, eh, sizeof(changed));
	capimage_elf_put(changed + (elf64 ? 40 : 32), table, elf64 ? 8 : 4, little);
	capimage_elf_put(changed + (elf64 ? 58 : 46), ss, 2, little);
	capimage_elf_put(changed + (elf64 ? 60 : 48), new_sn, 2, little);
	capimage_elf_put(changed + (elf64 ? 62 : 50), new_si, 2, little);
	int rc = write_at(fd, tail, end + sizeof(footer) - st.st_size, st.st_size);
	free(tail);
	if (rc < 0 || write_at(fd, changed, es, 0) < 0)
		return (fail(error, error_size, EIO, "cannot write ELF signature metadata"));
#undef TAIL
	return (0);
}
/* Structural ELF signature information, not signature verification. */
int
capimage_elf_info_fd(int fd, struct capimage_elf_info *info, char *error, size_t error_size)
{
	struct stat st;
	if (info == NULL || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0)
		return (fail(error, error_size, EFTYPE, "invalid ELF input"));
	int rc = capimage_elf_probe(elf_read, &fd, st.st_size, info);
	if (rc < 0) return (fail(error, error_size, EFTYPE, "malformed ELF signature"));
	if (rc == 0) {
		/* Preserve unsigned build-input validation and retired-note rejection. */
		struct image_note note;
		if (find_note(fd, &note, error, error_size) < 0 && errno != ENOENT) return (-1);
		info->original_size = st.st_size;
	}
	return (0);
}
/* Only a private writable copy may be removed. Authenticated rollback metadata must pass
 * embedded-key integrity before it controls restoration; this is not trust. */
int
capimage_remove(int fd, char *error, size_t error_size)
{
	struct capimage_elf_info info;
	struct capimage_policy policy;
	if (capimage_elf_info_fd(fd, &info, error, error_size) < 0) return (-1);
	if (info.version == 0) return (fail(error, error_size, ENOENT, "no signature to remove"));
	{
		if (capimage_verify_integrity(fd, &policy, error, error_size) < 0) return (-1);
		capimage_policy_free(&policy);
		if (write_at(fd, info.original_header, info.header_size, 0) < 0) return (-1);
	}
	if (ftruncate(fd, info.original_size) < 0)
		return (fail(error, error_size, errno, "cannot remove signature container"));
	return (0);
}
/* Generate unsigned policy input using the target assembler. No target
 * executable or signing key is needed during compilation. */
int
capimage_note(FILE *out, const void *data, size_t size, char *error, size_t error_size)
{
	const unsigned char *p = data;
	if (size == 0 || size > CAPIMAGE_POLICY_MAX || data == NULL)
		return (fail(error, error_size, EINVAL, "policy size out of bounds"));
	fprintf(out, ".section .5bsd.policy,\"\",%%progbits\n");
	for (size_t i = 0; i < size; i++) fprintf(out, ".byte %u\n", p[i]);
	fprintf(out, ".section .note.GNU-stack,\"\",%%progbits\n");
	return (ferror(out) ? fail(error, error_size, EIO, "cannot emit build policy") : 0);
}
/* Detached seals sign a digest that includes the complete fixed header with
 * signature zeroed, followed by the domain-separated content digest. */
static int
seal_digest(int fd, const char *domain, const struct capimage_header *header,
    unsigned char digest[32])
{
	struct capimage_header h = *header;
	struct stat st;
	unsigned char input[sizeof(h) + 32];
	unsigned n;
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
	    (uint64_t)st.st_size > UINT64_C(4) * 1024 * 1024 * 1024 ||
	    hash_fd(fd, st.st_size, 0, 0, domain, input + sizeof(h), 0, NULL, 0) < 0)
		return (-1);
	memset(h.signature, 0, sizeof(h.signature));
	memcpy(input, &h, sizeof(h));
	return (EVP_Digest(input, sizeof(input), digest, &n, EVP_sha256(), NULL) == 1 &&
	    n == 32 ? 0 : -1);
}
int
capimage_seal(int fd, int seal_fd, const char *domain, const char *keypath,
    char *error, size_t error_size)
{
	struct capimage_header h = {0};
	EVP_PKEY *key;
	unsigned char digest[32];
	size_t size = 32;
	int ok;
	if (domain == NULL || domain[0] == '\0' || keypath == NULL)
		return (fail(error, error_size, EINVAL, "domain and key are required"));
	memcpy(h.magic, magic, sizeof(magic));
	h.version = htole32(CAPIMAGE_SEAL_VERSION);
	key = read_key(keypath, true);
	ok = key != NULL && EVP_PKEY_get_raw_public_key(key, h.key, &size) == 1 && size == 32 &&
	    seal_digest(fd, domain, &h, digest) == 0 && sign_digest(key, digest, h.signature) == 0 &&
	    write_at(seal_fd, &h, sizeof(h), 0) == 0 && ftruncate(seal_fd, sizeof(h)) == 0;
	EVP_PKEY_free(key);
	return (ok ? 0 : fail(error, error_size, EIO, "cannot seal artifact"));
}
static int
check_seal(int fd, int seal_fd, const char *domain, const char *keypath,
    bool require_trust, char *error, size_t error_size)
{
	struct capimage_header h;
	struct stat st;
	unsigned char digest[32];
	if (domain == NULL || domain[0] == '\0')
		return (fail(error, error_size, EINVAL, "signature domain is required"));
	if (fstat(seal_fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size != sizeof(h) ||
	    read_at(seal_fd, &h, sizeof(h), 0) < 0 || memcmp(h.magic, magic, sizeof(magic)) != 0 ||
	    le32toh(h.version) != CAPIMAGE_SEAL_VERSION || h.policy_size != 0)
		return (fail(error, error_size, EFTYPE, "invalid detached signature format"));
	if ((require_trust && trusted_key(h.key, keypath) < 0) || seal_digest(fd, domain, &h, digest) < 0 ||
	    verify_digest(h.key, digest, h.signature) < 0)
		return (fail(error, error_size, EAUTH, "invalid or untrusted artifact signature"));
	return (0);
}

int
capimage_check_seal(int fd, int seal_fd, const char *domain, const char *keypath,
    char *error, size_t error_size)
{
	return (check_seal(fd, seal_fd, domain, keypath, true, error, error_size));
}
int
capimage_check_seal_integrity(int fd, int seal_fd, const char *domain,
    char *error, size_t error_size)
{
	return (check_seal(fd, seal_fd, domain, NULL, false, error, error_size));
}

static int
handle_info(int fd, struct capimage_info *info)
{
	struct capimage_info_request request = {
	    .version = CAPIMAGE_HANDLE_VERSION, .struct_size = sizeof(request),
	    .handle_fd = fd };

	if (mac_syscall(CAPIMAGE_MAC_POLICY, CAPIMAGE_HANDLE_INFO_SYSCALL,
	    &request) < 0)
		return (-1);
	*info = request.info;
	return (0);
}

/* Descriptor-based policy extraction from the verified kernel handle. */
int
capimage_prepare_fd(int fd, uint32_t flags, int *handle,
    struct capimage_info *info, char *error, size_t error_size)
{
	struct capimage_prepare request = { .version = CAPIMAGE_HANDLE_VERSION,
	    .struct_size = sizeof(request), .source_fd = fd, .flags = flags };
	struct image_note note;
	int result, saved;

	if (handle == NULL || info == NULL)
		return (fail(error, error_size, EINVAL, "handle and metadata are required"));
	*handle = -1;
	memset(info, 0, sizeof(*info));
	if ((flags & ~(CAPIMAGE_PREPARE_REQUIRED | CAPIMAGE_PREPARE_RAW_DIGEST |
	    CAPIMAGE_PREPARE_VVERIFY)) != 0)
		return (fail(error, error_size, EINVAL, "unknown preparation flags"));
	result = mac_syscall(CAPIMAGE_MAC_POLICY, CAPIMAGE_PREPARE_SYSCALL,
	    &request);
	if (result < 0)
		return (fail(error, error_size, errno, "kernel image preparation failed"));
	if (result == 0)
		return (0);
	result--;
	if (handle_info(result, info) < 0)
		goto invalid;
	if (info->version != CAPIMAGE_HANDLE_VERSION ||
	    info->struct_size != sizeof(*info) ||
	    info->container_version != CAPIMAGE_VERSION ||
	    info->policy_size == 0 || info->policy_size > CAPIMAGE_POLICY_MAX ||
	    info->file_size > CAPIMAGE_FILE_MAX ||
	    info->policy_offset > info->file_size ||
	    info->policy_size > info->file_size - info->policy_offset) {
		errno = EAUTH;
		goto invalid;
	}
	/* Kernel container integrity does not replace the ELF parser contract.
	 * The handle keeps this original fd's contents pinned during parsing. */
	if (find_note(fd, &note, error, error_size) < 0)
		goto invalid;
	if (!note.appended || (uint64_t)note.file_size != info->file_size ||
	    (uint64_t)note.offset + sizeof(note.header) != info->policy_offset ||
	    le32toh(note.header.policy_size) != info->policy_size ||
	    memcmp(note.header.key, info->key, sizeof(info->key)) != 0) {
		errno = EAUTH;
		goto invalid;
	}
	*handle = result;
	return (0);
invalid:
	saved = errno;
	close(result);
	memset(info, 0, sizeof(*info));
	return (fail(error, error_size, saved, "invalid pinned image metadata"));
}

int
capimage_handle_policy(int handle, struct capimage_policy *policy,
    char *error, size_t error_size)
{
	struct capimage_info info;
	unsigned char digest[32];
	unsigned digest_size;
	int saved;

	if (policy == NULL)
		return (fail(error, error_size, EINVAL, "policy result is required"));
	memset(policy, 0, sizeof(*policy));
	if (handle_info(handle, &info) < 0)
		return (fail(error, error_size, errno, "image handle metadata failed"));
	if (info.version != CAPIMAGE_HANDLE_VERSION ||
	    info.struct_size != sizeof(info) || info.policy_size == 0 ||
	    info.policy_size > CAPIMAGE_POLICY_MAX)
		return (fail(error, error_size, EAUTH, "invalid image handle policy size"));
	policy->size = info.policy_size;
	policy->data = malloc(policy->size + 1);
	if (policy->data == NULL)
		return (fail(error, error_size, ENOMEM, "cannot allocate policy"));
	if (read_at(handle, policy->data, policy->size, 0) < 0) {
		saved = errno;
		capimage_policy_free(policy);
		return (fail(error, error_size, saved, "image handle policy read failed"));
	}
	if (EVP_Digest(policy->data, policy->size, digest, &digest_size,
	    EVP_sha256(), NULL) != 1 || digest_size != sizeof(digest) ||
	    CRYPTO_memcmp(digest, info.policy_digest, sizeof(digest)) != 0) {
		capimage_policy_free(policy);
		return (fail(error, error_size, EAUTH, "image handle policy mismatch"));
	}
	policy->data[policy->size] = '\0';
	memcpy(policy->key, info.key, sizeof(policy->key));
	memcpy(policy->digest, info.image_digest, sizeof(policy->digest));
	return (0);
}

int
capimage_prepare_trusted_fd(int fd, uint32_t flags, const char *key,
    int *handle, struct capimage_info *info, char *error, size_t error_size)
{
	if (capimage_prepare_fd(fd, flags, handle, info, error, error_size) < 0)
		return (-1);
	if (*handle < 0)
		return (0);
	if (trusted_key(info->key, key) == 0)
		return (0);
	close(*handle);
	*handle = -1;
	memset(info, 0, sizeof(*info));
	return (fail(error, error_size, EAUTH, "pinned image signer is not trusted"));
}
