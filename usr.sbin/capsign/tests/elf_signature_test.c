/* SPDX-License-Identifier: BSD-2-Clause */
/* Replay the same mutations through userland and actual kernel consumers. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/endian.h>
#include <sys/sysctl.h>
#include <sys/mac.h>
#include <atf-c.h>
#include <capimage.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static char error[256];
static void
check(const char *name, int expected)
{
	struct capimage_policy policy;
	struct capimage_info info;
	int handle = -1, fd = open(name, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	int user = capimage_verify_integrity(fd, &policy, error, sizeof(error));
	int user_errno = errno;
	if (user == 0) capimage_policy_free(&policy);
	int kernel = mac_syscall("mac_veriexec", 5, (void *)(intptr_t)fd);
	int kernel_errno = errno;
	int prepare = capimage_prepare_fd(fd, 0, &handle, &info, error, sizeof(error));
	if (expected == 1) {
		ATF_REQUIRE_MSG(user == 0 && kernel == 0 && prepare == 0 && handle >= 0,
		    "%s valid: user=%d/%d kernel=%d/%d prepare=%d: %s", name,
		    user, user_errno, kernel, kernel_errno, prepare, error);
		ATF_REQUIRE_EQ(CAPIMAGE_VERSION, info.container_version);
	} else if (expected == 0) {
		ATF_REQUIRE_MSG(user < 0 && (user_errno == ENOENT || user_errno == ENOATTR),
		    "%s unsigned user state: %d/%d", name, user, user_errno);
		/* Required fd-check rejects unsigned; optional prepare remains absent. */
		ATF_REQUIRE_MSG(kernel < 0 && prepare == 0 && handle == -1,
		    "%s unsigned: kernel=%d/%d prepare=%d handle=%d", name,
		    kernel, kernel_errno, prepare, handle);
	} else {
		ATF_REQUIRE_MSG(user < 0 && kernel < 0 && prepare < 0,
		    "%s damaged accepted: user=%d/%d kernel=%d/%d prepare=%d", name,
		    user, user_errno, kernel, kernel_errno, prepare);
	}
	if (handle >= 0) close(handle);
	close(fd);
}
static void
publish(const char *path, const unsigned char *bytes, size_t size)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)size, write(fd, bytes, size));
	ATF_REQUIRE_EQ(0, close(fd));
}
ATF_TC(locator_parity);
ATF_TC_HEAD(locator_parity, tc)
{
	atf_tc_set_md_var(tc, "descr", "Identical ELF note mutation corpus through library, kernel fd check and PREPARE");
}
ATF_TC_BODY(locator_parity, tc)
{
	(void)tc;
	int feature = 0; size_t flen = sizeof(feature);
	if (sysctlbyname("kern.features.veriexec_capimage_elf_note", &feature, &flen, NULL, 0) != 0 || feature != 1)
		atf_tc_skip("requires ELF-native signature kernel");
	unsigned char secret[32] = {1}; /* deterministic fixture key, never enrollment */
	EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, secret, sizeof(secret));
	ATF_REQUIRE(key != NULL);
	FILE *fp = fopen("key", "w"); ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE_EQ(1, PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL));
	ATF_REQUIRE_EQ(0, fclose(fp)); EVP_PKEY_free(key);
	int input = open("/usr/bin/true", O_RDONLY); struct stat st;
	ATF_REQUIRE(input >= 0); ATF_REQUIRE_EQ(0, fstat(input, &st));
	unsigned char *raw = malloc(st.st_size); ATF_REQUIRE(raw != NULL);
	ATF_REQUIRE_EQ(st.st_size, read(input, raw, st.st_size)); close(input);
	publish("unsigned", raw, st.st_size); publish("signed", raw, st.st_size); free(raw);
	check("unsigned", 0);
	int fd = open("signed", O_RDWR); ATF_REQUIRE(fd >= 0);
	const char policy[] = "program = \"true\"; activation { exec = true; };\n";
	ATF_REQUIRE_MSG(capimage_embed(fd, policy, sizeof(policy)-1, error, sizeof(error)) == 0, "%s", error);
	ATF_REQUIRE_MSG(capimage_sign(fd, "key", error, sizeof(error)) == 0, "%s", error);
	ATF_REQUIRE_EQ(0, fstat(fd, &st));
	size_t size = st.st_size; unsigned char *bytes = malloc(size + 1);
	ATF_REQUIRE(bytes != NULL); ATF_REQUIRE_EQ((ssize_t)size, pread(fd, bytes, size, 0)); close(fd);
	check("signed", 1);
	/* AMD64 VM fixture; byte-order/class structural matrix lives in libcapimage. */
	ATF_REQUIRE_EQ(2, bytes[4]); ATF_REQUIRE_EQ(1, bytes[5]);
	uint64_t off = le64dec(bytes + size - 16);
	uint64_t shoff = le64dec(bytes + 40);
	uint16_t shnum = le16dec(bytes + 60);
	const uint64_t offsets[] = {24, 32, 40, 58, 60, 62, off-20, off-8,
	    off, off+8, off+16, off+48, off+112,
	    off+112+sizeof(policy)-1, shoff+(shnum-1)*64,
	    shoff+(shnum-1)*64+4, shoff+(shnum-1)*64+8,
	    size-32, size-24, size-16, size-1};
	for (size_t i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
		ATF_REQUIRE(offsets[i] < size);
		char name[40]; snprintf(name, sizeof(name), "mutated-%zu", i);
		bytes[offsets[i]] ^= 1; publish(name, bytes, size); check(name, -1); bytes[offsets[i]] ^= 1;
	}
	bytes[size] = 'x'; publish("appended", bytes, size+1); check("appended", -1);
	publish("truncated", bytes, size-1); check("truncated", -1);
	publish("footer-removed", bytes, size-32); check("footer-removed", -1);
	publish("sparse-appended", bytes, size);
	fd = open("sparse-appended", O_WRONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, CAPIMAGE_FILE_MAX + 1));
	ATF_REQUIRE_EQ(0, close(fd));
	check("sparse-appended", -1);
	free(bytes);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, locator_parity);
	return (atf_no_error());
}
