/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/endian.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/mac.h>
#include <sys/mman.h>
#include <sys/capsicum.h>
#include <atf-c.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "capimage.h"

static char error[256];
static const char policy_text[] = "attributes = [\"example.test\"];\n";
static void
keys(const char *secret, const char *public)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	EVP_PKEY *key = NULL;
	FILE *f;
	ATF_REQUIRE(ctx != NULL);
	ATF_REQUIRE_EQ(1, EVP_PKEY_keygen_init(ctx));
	ATF_REQUIRE_EQ(1, EVP_PKEY_keygen(ctx, &key));
	f = fopen(secret, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(1, PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL));
	ATF_REQUIRE_EQ(0, fclose(f));
	f = fopen(public, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(1, PEM_write_PUBKEY(f, key));
	ATF_REQUIRE_EQ(0, fclose(f));
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);
}
static void put16(void *p, uint16_t v, int little) { if (little) le16enc(p, v); else be16enc(p, v); }
static void put32(void *p, uint32_t v, int little) { if (little) le32enc(p, v); else be32enc(p, v); }
static void put64(void *p, uint64_t v, int little) { if (little) le64enc(p, v); else be64enc(p, v); }
/* Minimal ELF with a non-allocated raw policy section; both classes/orders. */
static int
fixture(int elf64, int little, int duplicate)
{
	unsigned char buf[4096] = {0};
	size_t ehsize = elf64 ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
	size_t phsize = elf64 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr);
	size_t shsize = elf64 ? sizeof(Elf64_Shdr) : sizeof(Elf32_Shdr);
	memcpy(buf, ELFMAG, SELFMAG);
	buf[EI_CLASS] = elf64 ? ELFCLASS64 : ELFCLASS32;
	buf[EI_DATA] = little ? ELFDATA2LSB : ELFDATA2MSB;
	buf[EI_VERSION] = EV_CURRENT;
	put16(buf + 16, ET_DYN, little);
	put16(buf + 18, elf64 ? EM_X86_64 : EM_386, little);
	put32(buf + 20, EV_CURRENT, little);
	if (elf64) {
		put64(buf + 32, ehsize, little); put64(buf + 40, 2048, little);
	} else {
		put32(buf + 28, ehsize, little); put32(buf + 32, 2048, little);
	}
	put16(buf + (elf64 ? 52 : 40), ehsize, little);
	put16(buf + (elf64 ? 54 : 42), phsize, little);
	put16(buf + (elf64 ? 56 : 44), 1, little);
	put16(buf + (elf64 ? 58 : 46), shsize, little);
	put16(buf + (elf64 ? 60 : 48), duplicate ? 4 : 3, little);
	put16(buf + (elf64 ? 62 : 50), 1, little);
	put32(buf + ehsize, PT_LOAD, little);
	/* Loadable bytes end before policy and section metadata. */
	if (elf64) put64(buf + ehsize + 32, 256, little);
	else put32(buf + ehsize + 16, 256, little);
	memcpy(buf + 1024, "\0.shstrtab\0.5bsd.policy", 24);
	memcpy(buf + 512, policy_text, sizeof(policy_text)-1);
	for (unsigned i = 1; i < (duplicate ? 4U : 3U); i++) {
		unsigned char *sh = buf + 2048 + i * shsize;
		put32(sh, i == 1 ? 1 : 11, little);
		put32(sh + 4, i == 1 ? SHT_STRTAB : SHT_PROGBITS, little);
		if (elf64) {
			put64(sh + 24, i == 1 ? 1024 : 512, little);
			put64(sh + 32, i == 1 ? 24 : sizeof(policy_text)-1, little);
		} else {
			put32(sh + 16, i == 1 ? 1024 : 512, little);
			put32(sh + 20, i == 1 ? 24 : sizeof(policy_text)-1, little);
		}
	}
	int fd = open("image", O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(sizeof(buf), write(fd, buf, sizeof(buf)));
	return (fd);
}
static void
valid(int fd)
{
	struct capimage_policy p;
	ATF_REQUIRE_MSG(capimage_verify(fd, "public", &p, error, sizeof(error)) == 0, "%s", error);
	ATF_REQUIRE_EQ(sizeof(policy_text) - 1, p.size);
	ATF_REQUIRE_EQ(0, memcmp(p.data, policy_text, p.size));
	capimage_policy_free(&p);
}
ATF_TC(system_trust);
ATF_TC_HEAD(system_trust, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(system_trust, tc)
{
	(void)tc;
	struct capimage_policy policy;
	bool required;
	char path[160], pem[4096];
	keys("secret", "public");
	int fd = fixture(1, 1, 0);
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(0, capimage_verify(fd, "public", &policy, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, mkdir("root", 0755));
	ATF_REQUIRE_EQ(0, mkdir("root/etc", 0755));
	ATF_REQUIRE_EQ(0, mkdir("root/etc/capability", 0755));
	ATF_REQUIRE_EQ(0, mkdir("root/etc/capability/keys", 0755));
	strlcpy(path, "root/etc/capability/keys/", sizeof(path));
	size_t prefix = strlen(path);
	for (unsigned i = 0; i < sizeof(policy.key); i++)
		snprintf(path + prefix + 2 * i, 3, "%02x", policy.key[i]);
	strlcat(path, ".pub", sizeof(path));
	capimage_policy_free(&policy);
	FILE *in = fopen("public", "r"), *out = fopen(path, "w");
	ATF_REQUIRE(in != NULL && out != NULL);
	size_t length = fread(pem, 1, sizeof(pem), in);
	ATF_REQUIRE(length > 0 && length < sizeof(pem));
	ATF_REQUIRE_EQ(length, fwrite(pem, 1, length, out));
	ATF_REQUIRE_EQ(0, fclose(in)); ATF_REQUIRE_EQ(0, fclose(out));
	ATF_REQUIRE_EQ(0, chmod(path, 0444));
	ATF_REQUIRE_EQ(0, chroot("root")); ATF_REQUIRE_EQ(0, chdir("/"));
	ATF_REQUIRE_EQ(0, capimage_signatures_required(&required, error, sizeof(error)));
	ATF_REQUIRE(!required);
	ATF_REQUIRE_EQ(0, capimage_verify(fd, NULL, &policy, error, sizeof(error)));
	capimage_policy_free(&policy);
	ATF_REQUIRE_EQ(0, chmod("/etc/capability", 0777));
	ATF_REQUIRE_EQ(-1, capimage_signatures_required(&required, error, sizeof(error)));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, NULL, &policy, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, chmod("/etc/capability", 0755));
	ATF_REQUIRE_EQ(0, chmod("/etc/capability/keys", 0777));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, NULL, &policy, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, chmod("/etc/capability/keys", 0755));
	ATF_REQUIRE_EQ(0, chmod(path + 4, 0666));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, NULL, &policy, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, chmod(path + 4, 0444));
	ATF_REQUIRE_EQ(0, rename("/etc/capability/keys", "/etc/capability/actual"));
	ATF_REQUIRE_EQ(0, symlink("actual", "/etc/capability/keys"));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, NULL, &policy, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, unlink("/etc/capability/keys"));
	ATF_REQUIRE_EQ(0, rename("/etc/capability/actual", "/etc/capability/keys"));
	int marker = open("/etc/capability/require-signatures", O_WRONLY | O_CREAT | O_EXCL, 0444);
	ATF_REQUIRE(marker >= 0); close(marker);
	ATF_REQUIRE_EQ(0, capimage_signatures_required(&required, error, sizeof(error)));
	ATF_REQUIRE(required);
	ATF_REQUIRE_EQ(0, unlink("/etc/capability/require-signatures"));
	ATF_REQUIRE_EQ(0, symlink("keys", "/etc/capability/require-signatures"));
	ATF_REQUIRE_EQ(-1, capimage_signatures_required(&required, error, sizeof(error)));
	close(fd);
}
ATF_TC_WITHOUT_HEAD(unsigned_note);
ATF_TC_BODY(unsigned_note, tc)
{
	(void)tc;
	struct capimage_policy p;
	int fd = fixture(1, 1, 0);
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, NULL, &p, error, sizeof(error)));
	ATF_REQUIRE_EQ(ENOATTR, errno);
	close(fd);
}
ATF_TC_WITHOUT_HEAD(roundtrip);
ATF_TC_BODY(roundtrip, tc)
{
	(void)tc;
	keys("secret", "public");
	for (int elf64 = 0; elf64 <= 1; elf64++)
		for (int little = 0; little <= 1; little++) {
			int fd = fixture(elf64, little, 0);
			ATF_REQUIRE_MSG(capimage_sign(fd, "secret", error, sizeof(error)) == 0, "%s", error);
			valid(fd);
			close(fd);
		}
}
ATF_TC_WITHOUT_HEAD(tamper);
ATF_TC_BODY(tamper, tc)
{
	struct capimage_policy p;
	/* ELF metadata, note name/metadata, key, signature, policy, image body. */
	const off_t offsets[] = {0, 24, 32, 56, 64, 256, 260, 264, 268,
	    276, 284, 288, 292, 324, 388, 512, 1024, 4095,
	    4096, 4104, 4108, 4112, 4144, 4208};
	(void)tc;
	keys("secret", "public");
	int fd = fixture(1, 1, 0);
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "secret", error, sizeof(error)));
	for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
		unsigned char old, changed;
		ATF_REQUIRE_EQ(1, pread(fd, &old, 1, offsets[i]));
		changed = old ^ 0x80;
		ATF_REQUIRE_EQ(1, pwrite(fd, &changed, 1, offsets[i]));
		ATF_REQUIRE_MSG(capimage_verify(fd, "public", &p, error, sizeof(error)) == -1,
		    "accepted tampering at %jd", (intmax_t)offsets[i]);
		ATF_REQUIRE_EQ(NULL, p.data);
		ATF_REQUIRE_EQ(1, pwrite(fd, &old, 1, offsets[i]));
		valid(fd);
	}
	close(fd);
}
ATF_TC_WITHOUT_HEAD(trust);
ATF_TC_BODY(trust, tc)
{
	struct capimage_policy p;
	(void)tc;
	keys("secret", "public"); keys("other-secret", "other-public");
	int fd = fixture(1, 1, 0);
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, "public", &p, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, "other-public", &p, error, sizeof(error)));
	ATF_REQUIRE_EQ(EAUTH, errno);
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, "missing", &p, error, sizeof(error)));
	ATF_REQUIRE_EQ(EAUTH, errno);
	ATF_REQUIRE_EQ(-1, capimage_sign(fd, NULL, error, sizeof(error)));
	valid(fd);
	close(fd);
}
ATF_TC_WITHOUT_HEAD(bounds);
ATF_TC_BODY(bounds, tc)
{
	struct capimage_policy p;
	uint64_t huge = UINT64_MAX;
	(void)tc;
	keys("secret", "public");
	int fd = fixture(1, 1, 1);
	ATF_REQUIRE_EQ(-1, capimage_sign(fd, "secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(EFTYPE, errno);
	close(fd);
	fd = fixture(1, 1, 0);
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(8, pwrite(fd, &huge, 8, 32));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, "public", &p, error, sizeof(error)));
	ATF_REQUIRE_EQ(EFTYPE, errno);
	close(fd);
	fd = fixture(1, 1, 0);
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(0, ftruncate(fd, 4095));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, "public", &p, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, ftruncate(fd, 4097));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, "public", &p, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, ftruncate(fd, 63));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, "public", &p, error, sizeof(error)));
	close(fd);
}
ATF_TC_WITHOUT_HEAD(detached);
ATF_TC_BODY(detached, tc)
{
	(void)tc;
	keys("secret", "public");
	int fd = fixture(1, 1, 0);
	int seal = open("seal", O_RDWR | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(seal >= 0);
	ATF_REQUIRE_EQ(0, capimage_seal(fd, seal, "bundle.v1", "secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(0, capimage_check_seal(fd, seal, "bundle.v1", "public", error, sizeof(error)));
	ATF_REQUIRE_EQ(-1, capimage_check_seal(fd, seal, "cache.v1", "public", error, sizeof(error)));
	ATF_REQUIRE_EQ(EAUTH, errno);
	ATF_REQUIRE_EQ(1, pwrite(fd, "x", 1, 1024));
	ATF_REQUIRE_EQ(-1, capimage_check_seal(fd, seal, "bundle.v1", "public", error, sizeof(error)));
	ATF_REQUIRE_EQ(0, ftruncate(seal, 111));
	ATF_REQUIRE_EQ(-1, capimage_check_seal(fd, seal, "bundle.v1", "public", error, sizeof(error)));
	ATF_REQUIRE_EQ(EFTYPE, errno);
	close(fd); close(seal);
}
ATF_TC_WITHOUT_HEAD(reproducible);
ATF_TC_BODY(reproducible, tc)
{
	unsigned char first[8192], second[8192];
	struct stat st;
	(void)tc;
	keys("secret", "public");
	int fd = fixture(1, 1, 0);
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(0, fstat(fd, &st));
	ATF_REQUIRE(st.st_size <= (off_t)sizeof(first));
	ATF_REQUIRE_EQ(st.st_size, pread(fd, first, st.st_size, 0));
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(st.st_size, pread(fd, second, st.st_size, 0));
	ATF_REQUIRE_EQ(0, memcmp(first, second, st.st_size));
	close(fd);
}
ATF_TC_WITHOUT_HEAD(appended_policy);
ATF_TC_BODY(appended_policy, tc)
{
	(void)tc;
	keys("secret", "public");
	for (int elf64 = 0; elf64 < 2; elf64++) {
		for (int little = 0; little < 2; little++) {
			int fd = fixture(elf64, little, 0);
			/* Remove the optional build policy section table. */
			unsigned char zero[8] = {0};
			ATF_REQUIRE_EQ(elf64 ? 8 : 4, pwrite(fd, zero, elf64 ? 8 : 4, elf64 ? 40 : 32));
			ATF_REQUIRE_EQ(2, pwrite(fd, zero, 2, elf64 ? 60 : 48));
			ATF_REQUIRE_EQ(0, capimage_embed(fd, policy_text, sizeof(policy_text)-1, error, sizeof(error)));
			ATF_REQUIRE_EQ(0, capimage_sign(fd, "secret", error, sizeof(error)));
			valid(fd);
			struct stat st;
			struct capimage_footer footer, bad;
			ATF_REQUIRE_EQ(0, fstat(fd, &st));
			ATF_REQUIRE_EQ(sizeof(footer), pread(fd, &footer, sizeof(footer), st.st_size-sizeof(footer)));
			ATF_REQUIRE_EQ(4096, le64toh(footer.offset));
			ATF_REQUIRE_EQ(0, capimage_embed(fd, policy_text, sizeof(policy_text)-1, error, sizeof(error)));
			ATF_REQUIRE_EQ(-1, capimage_embed(fd, "different", 9, error, sizeof(error)));
			bad = footer; bad.offset = htole64(UINT64_MAX);
			ATF_REQUIRE_EQ(sizeof(bad), pwrite(fd, &bad, sizeof(bad), st.st_size-sizeof(bad)));
			struct capimage_policy policy;
			ATF_REQUIRE_EQ(-1, capimage_verify(fd, "public", &policy, error, sizeof(error)));
			ATF_REQUIRE_EQ(sizeof(footer), pwrite(fd, &footer, sizeof(footer), st.st_size-sizeof(footer)));
			/* A load segment must not overlap the signature container. */
			unsigned char badsize[8];
			if (elf64) put64(badsize, st.st_size, little); else put32(badsize, st.st_size, little);
			ATF_REQUIRE_EQ(elf64 ? 8 : 4, pwrite(fd, badsize, elf64 ? 8 : 4,
			    (elf64 ? sizeof(Elf64_Ehdr) + 32 : sizeof(Elf32_Ehdr) + 16)));
			ATF_REQUIRE_EQ(-1, capimage_sign(fd, "secret", error, sizeof(error)));
			ATF_REQUIRE_EQ(EFTYPE, errno);
			close(fd);
		}
	}
}
ATF_TC_WITHOUT_HEAD(cache_payload);
ATF_TC_BODY(cache_payload, tc)
{
	(void)tc;
	keys("secret", "public");
	int fd = fixture(1, 1, 0);
	off_t size;
	ATF_REQUIRE_EQ(0, capimage_cache_size(fd, &size, error, sizeof(error)));
	ATF_REQUIRE_EQ(4096, size);
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(0, capimage_cache_size(fd, &size, error, sizeof(error)));
	ATF_REQUIRE_EQ(4096, size);
	struct stat st;
	struct capimage_footer footer;
	ATF_REQUIRE_EQ(0, fstat(fd, &st));
	ATF_REQUIRE_EQ(sizeof(footer), pread(fd, &footer, sizeof(footer), st.st_size-sizeof(footer)));
	unsigned char container[2048];
	size_t bytes = st.st_size - 4096;
	ATF_REQUIRE(bytes <= sizeof(container));
	ATF_REQUIRE_EQ((ssize_t)bytes, pread(fd, container, bytes, 4096));
	footer.offset = htole64(st.st_size);
	memcpy(container + bytes - sizeof(footer), &footer, sizeof(footer));
	ATF_REQUIRE_EQ((ssize_t)bytes, pwrite(fd, container, bytes, st.st_size));
	ATF_REQUIRE_EQ(-1, capimage_cache_size(fd, &size, error, sizeof(error)));
	close(fd);
	fd = fixture(1, 1, 0);
	unsigned char ph[sizeof(Elf64_Phdr)] = {0}, note[24] = {0};
	put32(ph, PT_NOTE, 1); put64(ph+8, 256, 1); put64(ph+32, sizeof(note), 1);
	put32(note, 5, 1); put32(note+4, 4, 1); put32(note+8, CAPIMAGE_NOTE_TYPE, 1);
	memcpy(note+12, "5BSD", 5);
	ATF_REQUIRE_EQ(sizeof(ph), pwrite(fd, ph, sizeof(ph), sizeof(Elf64_Ehdr)));
	ATF_REQUIRE_EQ(sizeof(note), pwrite(fd, note, sizeof(note), 256));
	ATF_REQUIRE_EQ(-1, capimage_cache_size(fd, &size, error, sizeof(error)));
	ATF_REQUIRE(strstr(error, "retired inline") != NULL);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(personal_integrity);
ATF_TC_BODY(personal_integrity, tc)
{
	struct capimage_policy policy, trusted;
	int fd, seal;
	unsigned char byte;

	keys("personal-key", "personal-public");
	fd = fixture(1, 1, 0);
	ATF_REQUIRE_EQ(-1, capimage_verify_integrity(fd, &policy, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "personal-key", error, sizeof(error)));
	ATF_REQUIRE_EQ(-1, capimage_verify(fd, NULL, &policy, error, sizeof(error)));
	ATF_REQUIRE_EQ(EAUTH, errno);
	ATF_REQUIRE_EQ(0, capimage_verify_integrity(fd, &policy, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, capimage_verify(fd, "personal-public", &trusted, error, sizeof(error)));
	ATF_CHECK_EQ(0, memcmp(policy.digest, trusted.digest, sizeof(policy.digest)));
	ATF_CHECK_EQ(0, memcmp(policy.key, trusted.key, sizeof(policy.key)));
	ATF_CHECK_STREQ((char *)policy.data, policy_text);
	capimage_policy_free(&policy); capimage_policy_free(&trusted);
	seal = open("personal-seal", O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(seal >= 0);
	ATF_REQUIRE_EQ(0, capimage_seal(fd, seal, "personal-test", "personal-key", error, sizeof(error)));
	ATF_REQUIRE_EQ(-1, capimage_check_seal(fd, seal, "personal-test", NULL, error, sizeof(error)));
	ATF_REQUIRE_EQ(0, capimage_check_seal_integrity(fd, seal, "personal-test", error, sizeof(error)));
	ATF_REQUIRE_EQ(-1, capimage_check_seal_integrity(fd, seal, "other-domain", error, sizeof(error)));
	ATF_REQUIRE_EQ(1, pread(fd, &byte, 1, 256)); byte ^= 1;
	ATF_REQUIRE_EQ(1, pwrite(fd, &byte, 1, 256));
	ATF_REQUIRE_EQ(-1, capimage_verify_integrity(fd, &policy, error, sizeof(error)));
	ATF_REQUIRE_EQ(-1, capimage_check_seal_integrity(fd, seal, "personal-test", error, sizeof(error)));
	close(seal); close(fd);
}

static void
require_handle_kernel(void)
{
	int present = 0;
	size_t size = sizeof(present);

	if (sysctlbyname("kern.features.veriexec_capimage_handle", &present,
	    &size, NULL, 0) != 0 || present != 1)
		atf_tc_skip("requires the phase-one image-handle kernel in the VM");
}

/* Do not turn a backend rejection into a skipped pin/lifetime assertion.
 * Run these cases with Kyua TMPDIR on the filesystem being audited. */
static void
require_handle_filesystem(void)
{
 struct statfs fs;
 ATF_REQUIRE_EQ(0, statfs(".", &fs));
 ATF_REQUIRE_MSG(strcmp(fs.f_fstypename, "ufs") == 0 ||
     strcmp(fs.f_fstypename, "zfs") == 0,
     "handle lifetime tests require UFS/ZFS workdir, got %s; set Kyua TMPDIR",
     fs.f_fstypename);
}

ATF_TC_WITHOUT_HEAD(handle_arguments);
ATF_TC_BODY(handle_arguments, tc)
{
	struct capimage_info info;
	int handle = 42;

	ATF_REQUIRE_EQ(-1, capimage_prepare_fd(-1, UINT32_MAX, &handle,
	    &info, error, sizeof(error)));
	ATF_REQUIRE_EQ(EINVAL, errno);
	ATF_REQUIRE_EQ(-1, handle);
	ATF_REQUIRE_EQ(-1, capimage_handle_policy(-1, NULL, error, sizeof(error)));
	ATF_REQUIRE_EQ(EINVAL, errno);
	ATF_REQUIRE_EQ(200U, sizeof(info));
	ATF_REQUIRE_EQ(48U, sizeof(struct capimage_prepare));
}

ATF_TC_WITHOUT_HEAD(handle_unsigned_and_bad);
ATF_TC_BODY(handle_unsigned_and_bad, tc)
{
	struct capimage_info info;
	struct capimage_policy output;
	struct capimage_prepare request = { .version = CAPIMAGE_HANDLE_VERSION,
	    .struct_size = sizeof(request), .source_fd = -1 };
	int handle, fd;

	require_handle_kernel();require_handle_filesystem();
	fd = fixture(1, 1, 0); /* O_RDWR must not make unsigned introspection busy. */
	ATF_REQUIRE_EQ(0, capimage_prepare_fd(fd, 0, &handle, &info, error, sizeof(error)));
	ATF_REQUIRE_EQ(-1, handle);
	ATF_REQUIRE_EQ(-1, capimage_prepare_fd(fd, CAPIMAGE_PREPARE_REQUIRED,
	    &handle, &info, error, sizeof(error)));
	ATF_REQUIRE_EQ(ENOATTR, errno);
	keys("handle-secret", "handle-public");
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "handle-secret", error, sizeof(error)));
	ATF_REQUIRE_EQ(-1, capimage_prepare_fd(fd, 0, &handle, &info, error, sizeof(error)));
	ATF_REQUIRE_EQ(ETXTBSY, errno);
	unsigned char byte;
	ATF_REQUIRE_EQ(1, pread(fd, &byte, 1, 256));byte ^= 1;
	ATF_REQUIRE_EQ(1, pwrite(fd, &byte, 1, 256));close(fd);
	fd = open("image", O_RDONLY);ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(-1, capimage_prepare_fd(fd, 0, &handle, &info, error, sizeof(error)));
	ATF_REQUIRE_EQ(EAUTH, errno);ATF_REQUIRE_EQ(-1, handle);
	ATF_REQUIRE_EQ(-1,capimage_handle_policy(fd,&output,error,sizeof(error)));
	ATF_REQUIRE_EQ(EINVAL,errno);
	close(fd);fd = open("image", O_RDWR);ATF_REQUIRE(fd >= 0);close(fd);
	request.reserved[0] = 1;
	ATF_REQUIRE_EQ(-1, mac_syscall(CAPIMAGE_MAC_POLICY,
	    CAPIMAGE_PREPARE_SYSCALL, &request));
	ATF_REQUIRE_EQ(EINVAL, errno);
	ATF_REQUIRE_EQ(-1, mac_syscall(CAPIMAGE_MAC_POLICY,
	    CAPIMAGE_PREPARE_SYSCALL, (void *)(uintptr_t)1));
	ATF_REQUIRE_EQ(EFAULT, errno);
}

ATF_TC_WITHOUT_HEAD(handle_policy_and_alias);
ATF_TC_BODY(handle_policy_and_alias, tc)
{
	struct capimage_info info;
	struct capimage_policy policy, old;
	struct stat st;
	unsigned char *raw, digest[32];
	unsigned digest_size;
	int fd, handle, copied, writer;
	char bytes[128];

	require_handle_kernel();require_handle_filesystem();keys("handle-secret", "handle-public");
	fd=fixture(1,1,0);ATF_REQUIRE_EQ(0,capimage_sign(fd,"handle-secret",error,sizeof(error)));
	close(fd);fd=open("image",O_RDONLY);ATF_REQUIRE(fd>=0);
	ATF_REQUIRE_MSG(capimage_prepare_fd(fd,CAPIMAGE_PREPARE_REQUIRED |
	    CAPIMAGE_PREPARE_RAW_DIGEST,&handle,&info,error,sizeof(error))==0,"%s",error);
	ATF_REQUIRE(handle>=0);ATF_REQUIRE(fcntl(handle,F_GETFD)&FD_CLOEXEC);
	ATF_REQUIRE_EQ(0,capimage_verify_integrity(fd,&old,error,sizeof(error)));
	ATF_REQUIRE(memcmp(old.digest,info.image_digest,32)==0);
	ATF_REQUIRE_EQ(0,capimage_handle_policy(handle,&policy,error,sizeof(error)));
	ATF_REQUIRE_EQ(old.size,policy.size);ATF_REQUIRE(memcmp(old.data,policy.data,old.size)==0);
	ATF_REQUIRE_EQ(0,fstat(fd,&st));raw=malloc(st.st_size);ATF_REQUIRE(raw!=NULL);
	ATF_REQUIRE_EQ(st.st_size,pread(fd,raw,st.st_size,0));
	ATF_REQUIRE_EQ(1,EVP_Digest(raw,st.st_size,digest,&digest_size,EVP_sha256(),NULL));
	ATF_REQUIRE(memcmp(digest,info.raw_digest,32)==0);free(raw);
	ATF_REQUIRE(memcmp(info.raw_digest,info.image_digest,32)!=0);
	ATF_REQUIRE_EQ((off_t)policy.size,lseek(handle,0,SEEK_END));
	ATF_REQUIRE_EQ(0,read(handle,bytes,sizeof(bytes)));
	ATF_REQUIRE_EQ(0,lseek(handle,0,SEEK_SET));
	ATF_REQUIRE_EQ((ssize_t)policy.size,read(handle,bytes,sizeof(bytes)));
	ATF_REQUIRE_EQ(-1,pwrite(handle,"x",1,0));
	ATF_REQUIRE_EQ(0,link("image","alias"));
	ATF_REQUIRE_EQ(0,rename("image","old-image"));
	writer=open("image",O_RDWR|O_CREAT|O_EXCL,0600);ATF_REQUIRE(writer>=0);close(writer);
	ATF_REQUIRE_EQ(-1,open("alias",O_WRONLY));ATF_REQUIRE_EQ(ETXTBSY,errno);
	copied=dup(handle);ATF_REQUIRE(copied>=0);close(handle);close(fd);
	ATF_REQUIRE_EQ(-1,open("old-image",O_WRONLY));ATF_REQUIRE_EQ(ETXTBSY,errno);
	capimage_policy_free(&old);
	ATF_REQUIRE_EQ(0,capimage_handle_policy(copied,&old,error,sizeof(error)));
	capimage_policy_free(&old);capimage_policy_free(&policy);
	close(copied);writer=open("alias",O_WRONLY);ATF_REQUIRE(writer>=0);close(writer);
}

ATF_TC_WITHOUT_HEAD(handle_fork_lifetime);
ATF_TC_BODY(handle_fork_lifetime, tc)
{
	struct capimage_info info;
	int fd,handle,ready[2],release[2],status,writer;
	char byte;
	pid_t child;

	require_handle_kernel();require_handle_filesystem();keys("handle-secret","handle-public");
	fd=fixture(1,1,0);ATF_REQUIRE_EQ(0,capimage_sign(fd,"handle-secret",error,sizeof(error)));
	close(fd);fd=open("image",O_RDONLY);ATF_REQUIRE(fd>=0);
	ATF_REQUIRE_EQ(0,capimage_prepare_fd(fd,0,&handle,&info,error,sizeof(error)));
	ATF_REQUIRE(handle>=0);ATF_REQUIRE_EQ(0,pipe(ready));ATF_REQUIRE_EQ(0,pipe(release));
	child=fork();ATF_REQUIRE(child>=0);
	if(child==0) {
		close(fd);close(ready[0]);close(release[1]);
		if(write(ready[1],"x",1)!=1||read(release[0],&byte,1)!=1)_exit(1);
		close(handle);_exit(0);
	}
	close(ready[1]);close(release[0]);close(fd);close(handle);
	ATF_REQUIRE_EQ(1,read(ready[0],&byte,1));
	ATF_REQUIRE_EQ(-1,open("image",O_WRONLY));ATF_REQUIRE_EQ(ETXTBSY,errno);
	ATF_REQUIRE_EQ(1,write(release[1],"x",1));
	ATF_REQUIRE_EQ(child,waitpid(child,&status,0));ATF_REQUIRE(WIFEXITED(status)&&WEXITSTATUS(status)==0);
	writer=open("image",O_WRONLY);ATF_REQUIRE(writer>=0);close(writer);
	close(ready[0]);close(release[1]);
}

ATF_TC_WITHOUT_HEAD(handle_fd_exhaustion);
ATF_TC_BODY(handle_fd_exhaustion, tc)
{
	struct capimage_info info;
	struct rlimit saved,limit;
	int fd,handle,fill[64],n=0,writer;

	require_handle_kernel();require_handle_filesystem();keys("handle-secret","handle-public");
	fd=fixture(1,1,0);ATF_REQUIRE_EQ(0,capimage_sign(fd,"handle-secret",error,sizeof(error)));
	close(fd);fd=open("image",O_RDONLY);ATF_REQUIRE(fd>=0);
	ATF_REQUIRE_EQ(0,getrlimit(RLIMIT_NOFILE,&saved));limit=saved;limit.rlim_cur=32;
	ATF_REQUIRE_EQ(0,setrlimit(RLIMIT_NOFILE,&limit));
	while(n<64&&(fill[n]=open("/dev/null",O_RDONLY))>=0)n++;
	ATF_REQUIRE(n<64);ATF_REQUIRE_EQ(EMFILE,errno);
	ATF_REQUIRE_EQ(-1,capimage_prepare_fd(fd,0,&handle,&info,error,sizeof(error)));
	ATF_REQUIRE_EQ(EMFILE,errno);ATF_REQUIRE_EQ(-1,handle);
	while(n>0)close(fill[--n]);
	ATF_REQUIRE_EQ(0,setrlimit(RLIMIT_NOFILE,&saved));close(fd);
	writer=open("image",O_WRONLY);ATF_REQUIRE(writer>=0);close(writer);
}

ATF_TC_WITHOUT_HEAD(handle_mapping_and_rights);
ATF_TC_BODY(handle_mapping_and_rights, tc)
{
	struct capimage_info info;
	struct capimage_info_request *request;
	cap_rights_t rights;
	void *mapping, *fault;
	long page = sysconf(_SC_PAGESIZE);
	int fd, handle, limited, writer;

	require_handle_kernel();require_handle_filesystem(); keys("handle-secret", "handle-public");
	fd = fixture(1, 1, 0);
	mapping = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	ATF_REQUIRE(mapping != MAP_FAILED);
	ATF_REQUIRE_EQ(0, capimage_sign(fd, "handle-secret", error, sizeof(error)));
	close(fd); fd = open("image", O_RDONLY); ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(-1, capimage_prepare_fd(fd, 0, &handle, &info, error, sizeof(error)));
	ATF_REQUIRE_EQ(ETXTBSY, errno);
	ATF_REQUIRE_EQ(0, munmap(mapping, page));
	limited = dup(fd); ATF_REQUIRE(limited >= 0);
	ATF_REQUIRE_EQ(0, cap_rights_limit(limited, cap_rights_init(&rights, CAP_READ)));
	ATF_REQUIRE_EQ(-1, capimage_prepare_fd(limited, 0, &handle, &info, error, sizeof(error)));
	ATF_REQUIRE_EQ(ENOTCAPABLE, errno); ATF_REQUIRE_EQ(-1, handle); close(limited);
	ATF_REQUIRE_EQ(7, lseek(fd, 7, SEEK_SET));
	ATF_REQUIRE_EQ(0, capimage_prepare_fd(fd, 0, &handle, &info, error, sizeof(error)));
	ATF_REQUIRE(handle >= 0); ATF_REQUIRE_EQ(7, lseek(fd, 0, SEEK_CUR));
	fault = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	ATF_REQUIRE(fault != MAP_FAILED);
	ATF_REQUIRE_EQ(0, mprotect((char *)fault + page, page, PROT_NONE));
	request = (void *)((char *)fault + page - offsetof(struct capimage_info_request, info));
	request->version = CAPIMAGE_HANDLE_VERSION; request->struct_size = sizeof(*request);
	request->handle_fd = handle; request->reserved = 0;
	ATF_REQUIRE_EQ(-1, mac_syscall(CAPIMAGE_MAC_POLICY, CAPIMAGE_HANDLE_INFO_SYSCALL, request));
	ATF_REQUIRE_EQ(EFAULT, errno);
	ATF_REQUIRE_EQ(-1, open("image", O_WRONLY)); ATF_REQUIRE_EQ(ETXTBSY, errno);
	ATF_REQUIRE_EQ(0, munmap(fault, page * 2));
	close(handle); close(fd);
	writer = open("image", O_WRONLY); ATF_REQUIRE(writer >= 0); close(writer);
}

ATF_TC_WITH_CLEANUP(handle_tmpfs_unsupported);
ATF_TC_HEAD(handle_tmpfs_unsupported, tc)
{
 atf_tc_set_md_var(tc, "descr", "tmpfs never publishes mutable handles; unsigned introspection remains unpinned");
}
ATF_TC_BODY(handle_tmpfs_unsupported, tc)
{
 struct capimage_info info;
 struct capimage_policy policy;
 struct statfs fs;
 char path[PATH_MAX];
 const char *root;
 FILE *record;
 int fd, handle, writer;
 void *mapping;
 unsigned char byte;
 long page = sysconf(_SC_PAGESIZE);
 require_handle_kernel();
 root = atf_tc_get_config_var_wd(tc, "tmpfs_test_root", "/tmp");
 ATF_REQUIRE(snprintf(path, sizeof(path), "%s/capimage-tmpfs.XXXXXX", root) < (int)sizeof(path));
 ATF_REQUIRE(mkdtemp(path) != NULL);
 record = fopen("tmpfs-fixture-path", "w");ATF_REQUIRE(record != NULL);
 ATF_REQUIRE(fprintf(record, "%s\n", path) > 0);ATF_REQUIRE_EQ(0, fclose(record));
 ATF_REQUIRE_EQ(0, chdir(path));ATF_REQUIRE_EQ(0, statfs(".", &fs));
 ATF_REQUIRE_MSG(strcmp(fs.f_fstypename, "tmpfs") == 0,
     "tmpfs containment test needs actual tmpfs, got %s", fs.f_fstypename);
 fd = fixture(1, 1, 0);
 mapping = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
 ATF_REQUIRE(mapping != MAP_FAILED);
 ATF_REQUIRE_EQ(0, capimage_prepare_fd(fd, 0, &handle, &info, error, sizeof(error)));
 ATF_REQUIRE_EQ(-1, handle);
 ATF_REQUIRE_EQ(-1, capimage_prepare_fd(fd, CAPIMAGE_PREPARE_REQUIRED,
     &handle, &info, error, sizeof(error)));ATF_REQUIRE_EQ(ENOATTR, errno);
 keys("handle-secret", "handle-public");
 ATF_REQUIRE_EQ(0, capimage_sign(fd, "handle-secret", error, sizeof(error)));
 close(fd);fd = open("image", O_RDONLY);ATF_REQUIRE(fd >= 0);
 ATF_REQUIRE_EQ(0, capimage_verify_integrity(fd, &policy, error, sizeof(error)));
 capimage_policy_free(&policy);
 for(unsigned i=0;i<2;i++) {
  ATF_REQUIRE_EQ(-1, capimage_prepare_fd(fd, i ? CAPIMAGE_PREPARE_REQUIRED : 0,
      &handle, &info, error, sizeof(error)));
  ATF_REQUIRE_EQ(EOPNOTSUPP, errno);ATF_REQUIRE_EQ(-1, handle);
 }
 /* The mapping is really mutable, rather than a guessed backend property. */
 byte = ((unsigned char *)mapping)[256];((unsigned char *)mapping)[256] = byte ^ 1;
 ATF_REQUIRE_EQ(-1, capimage_verify_integrity(fd, &policy, error, sizeof(error)));
 ATF_REQUIRE_EQ(EAUTH, errno);((unsigned char *)mapping)[256] = byte;
 ATF_REQUIRE_EQ(0, munmap(mapping, page));
 ATF_REQUIRE_EQ(-1, capimage_prepare_fd(fd, 0, &handle, &info, error, sizeof(error)));
 ATF_REQUIRE_EQ(EOPNOTSUPP, errno);ATF_REQUIRE_EQ(-1, handle);
 writer = open("image", O_WRONLY);ATF_REQUIRE(writer >= 0);close(writer);close(fd);
}
ATF_TC_CLEANUP(handle_tmpfs_unsupported, tc)
{
 char path[PATH_MAX];FILE *record;int dir;
 (void)tc;
 record=fopen("tmpfs-fixture-path","r");if(record==NULL)return;
 if(fgets(path,sizeof(path),record)==NULL){fclose(record);return;}
 fclose(record);path[strcspn(path,"\n")]='\0';
 dir=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(dir<0)return;
 (void)unlinkat(dir,"image",0);(void)unlinkat(dir,"handle-secret",0);
 (void)unlinkat(dir,"handle-public",0);close(dir);(void)rmdir(path);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, handle_tmpfs_unsupported);
	ATF_TP_ADD_TC(tp, handle_mapping_and_rights);
	ATF_TP_ADD_TC(tp, handle_arguments);
	ATF_TP_ADD_TC(tp, handle_unsigned_and_bad);
	ATF_TP_ADD_TC(tp, handle_policy_and_alias);
	ATF_TP_ADD_TC(tp, handle_fork_lifetime);
	ATF_TP_ADD_TC(tp, handle_fd_exhaustion);
	ATF_TP_ADD_TC(tp, personal_integrity);
	ATF_TP_ADD_TC(tp, cache_payload);
	ATF_TP_ADD_TC(tp, appended_policy);
	ATF_TP_ADD_TC(tp, system_trust);
	ATF_TP_ADD_TC(tp, unsigned_note);
	ATF_TP_ADD_TC(tp, roundtrip);
	ATF_TP_ADD_TC(tp, tamper);
	ATF_TP_ADD_TC(tp, trust);
	ATF_TP_ADD_TC(tp, bounds);
	ATF_TP_ADD_TC(tp, detached);
	ATF_TP_ADD_TC(tp, reproducible);
	return (atf_no_error());
}
