/* Isolated coverage for the on-disk SMP bond-secret lifecycle. */
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "hci_util.h"
#include "smp.h"
#include "spec_smp_secret_oracles.h"

#define TEST_LINKS_SMP
#include "test_common.h"

int __real_open(const char *, int, ...);
int __wrap_open(const char *, int, ...);
int __real_openat(int, const char *, int, ...);
int __wrap_openat(int, const char *, int, ...);
ssize_t __real_write(int, const void *, size_t);
ssize_t __wrap_write(int, const void *, size_t);

static int inject_create_race;
static bool inject_short_write;
static int secret_fd = -1;

int
__wrap_open(const char *path, int flags, ...)
{
	mode_t mode = 0;
	va_list ap;
	int fd;

	if ((flags & O_CREAT) != 0) {
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	if (strcmp(path, BLUED_BONDDB_DEFAULT ".key") == 0)
		path = "bonds.key";
	fd = (flags & O_CREAT) != 0 ? __real_open(path, flags, mode) :
	    __real_open(path, flags);
	if (inject_short_write && strcmp(path, "bonds.key") == 0 &&
	    fd >= 0)
		secret_fd = fd;
	return (fd);
}

int
__wrap_openat(int dirfd, const char *path, int flags, ...)
{
	uint8_t key[BLUED_TEST_BOND_SECRET_SIZE];
	mode_t mode = 0;
	va_list ap;
	int fd;

	if ((flags & O_CREAT) != 0) {
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	if (inject_create_race != 0 && strcmp(path, "bonds.key") == 0) {
		if (inject_create_race == 1 && (flags & O_CREAT) == 0) {
			inject_create_race = 2;
			errno = ENOENT;
			return (-1);
		}
		if (inject_create_race == 2 && (flags & O_CREAT) != 0) {
			/* Simulate a complete key won by a competing process. */
			memset(key, BLUED_TEST_SECRET_RACING_BYTE, sizeof(key));
			fd = __real_openat(dirfd, path,
			    O_WRONLY | O_CREAT | O_TRUNC,
			    BLUED_TEST_BOND_SECRET_MODE);
			ATF_REQUIRE(fd >= 0);
			ATF_REQUIRE_EQ((ssize_t)sizeof(key),
			    __real_write(fd, key, sizeof(key)));
			ATF_REQUIRE_EQ(0, close(fd));
			inject_create_race = 0;
			errno = EEXIST;
			return (-1);
		}
	}
	fd = (flags & O_CREAT) != 0 ?
	    __real_openat(dirfd, path, flags, mode) :
	    __real_openat(dirfd, path, flags);
	if (inject_short_write && strcmp(path, "bonds.key") == 0 && fd >= 0)
		secret_fd = fd;
	return (fd);
}

ssize_t
__wrap_write(int fd, const void *buf, size_t len)
{

	if (inject_short_write && fd == secret_fd) {
		inject_short_write = false;
		secret_fd = -1;
		return (len == 0 ? 0 : __real_write(fd, buf, 1));
	}
	return (__real_write(fd, buf, len));
}

int
hci_send_raw_cmd(int fd __unused, uint16_t opcode __unused,
    const void *params __unused, uint8_t len __unused)
{

	return (0);
}

int
hci_wait_encryption(int fd __unused, uint16_t handle __unused,
    int timeout __unused)
{

	return (0);
}

int
hci_le_ltk_request_reply(int fd __unused, uint16_t handle __unused,
    const uint8_t ltk[16] __unused)
{

	return (0);
}

static void
write_secret(const void *data, size_t len)
{
	int fd;

	fd = open("bonds.key", O_WRONLY | O_CREAT | O_TRUNC,
	    BLUED_TEST_BOND_SECRET_MODE);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ((ssize_t)len, write(fd, data, len));
	ATF_REQUIRE_EQ(0, close(fd));
}

static void
db_init(struct smp_bond_db *db, int *dirfd)
{
	int fd;

	(void)unlink("bonds");
	(void)unlink("bonds.tmp");
	memset(db, 0, sizeof(*db));
	fd = open("bonds", O_RDWR | O_CREAT | O_TRUNC,
	    BLUED_TEST_BOND_SECRET_MODE);
	ATF_REQUIRE(fd >= 0);
	*dirfd = open(".", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(*dirfd >= 0);
	db->fd = fd;
	smp_bond_db_set_atomic(db, *dirfd, "bonds");
}

static void
db_fini(struct smp_bond_db *db, int dirfd)
{

	close(db->fd);
	close(dirfd);
	(void)unlink("bonds");
	(void)unlink("bonds.tmp");
	(void)unlink("bonds.key");
}

ATF_TC_WITHOUT_HEAD(create_and_cache);
ATF_TC_BODY(create_and_cache, tc)
{
	struct smp_bond_db db;
	struct stat st;
	uint8_t cached[BLUED_TEST_BOND_SECRET_SIZE];
	int dirfd;

	(void)unlink("bonds.key");
	db_init(&db, &dirfd);
	ATF_REQUIRE_EQ(0, smp_bond_db_save(&db));
	ATF_REQUIRE_EQ(0, stat("bonds.key", &st));
	ATF_CHECK_EQ(BLUED_TEST_BOND_SECRET_SIZE, st.st_size);
	ATF_CHECK_EQ(BLUED_TEST_BOND_SECRET_MODE, st.st_mode & 0777);
	ATF_CHECK(db.has_bond_secret);
	memcpy(cached, db.bond_secret, sizeof(cached));
	ATF_REQUIRE_EQ(0, unlink("bonds.key"));
	ATF_CHECK_EQ(0, smp_bond_db_save(&db));
	ATF_CHECK(memcmp(cached, db.bond_secret, sizeof(cached)) == 0);
	ATF_CHECK_EQ(-1, access("bonds.key", F_OK));
	db_fini(&db, dirfd);
}

ATF_TC_WITHOUT_HEAD(load_existing);
ATF_TC_BODY(load_existing, tc)
{
	struct smp_bond_db db;
	uint8_t secret[BLUED_TEST_BOND_SECRET_SIZE];
	int dirfd;

	memset(secret, BLUED_TEST_SECRET_EXISTING_BYTE, sizeof(secret));
	write_secret(secret, sizeof(secret));
	db_init(&db, &dirfd);
	ATF_CHECK_EQ(0, smp_bond_db_save(&db));
	ATF_CHECK(db.has_bond_secret);
	ATF_CHECK(memcmp(secret, db.bond_secret, sizeof(secret)) == 0);
	db_fini(&db, dirfd);
}

ATF_TC_WITHOUT_HEAD(reject_truncated_or_nonregular);
ATF_TC_BODY(reject_truncated_or_nonregular, tc)
{
	struct smp_bond_db db;
	uint8_t short_secret[BLUED_TEST_BOND_SECRET_TRUNCATED_SIZE];
	int dirfd;

	memset(short_secret, 0x33, sizeof(short_secret));
	write_secret(short_secret, sizeof(short_secret));
	db_init(&db, &dirfd);
	ATF_CHECK_EQ(-1, smp_bond_db_save(&db));
	db_fini(&db, dirfd);

	ATF_REQUIRE_EQ(0, mkdir("bonds.key", BLUED_TEST_DIRECTORY_MODE));
	db_init(&db, &dirfd);
	ATF_CHECK_EQ(-1, smp_bond_db_save(&db));
	db_fini(&db, dirfd);
	ATF_REQUIRE_EQ(0, rmdir("bonds.key"));

	/* A complete root with group/other permissions is equally untrusted. */
	{
		uint8_t secret[BLUED_TEST_BOND_SECRET_SIZE];
		memset(secret, BLUED_TEST_SECRET_INSECURE_BYTE, sizeof(secret));
		write_secret(secret, sizeof(secret));
		ATF_REQUIRE_EQ(0, chmod("bonds.key",
		    BLUED_TEST_BOND_SECRET_INSECURE_MODE));
	}
	db_init(&db, &dirfd);
	ATF_CHECK_EQ(-1, smp_bond_db_save(&db));
	db_fini(&db, dirfd);
}

ATF_TC_WITHOUT_HEAD(create_race_and_short_write);
ATF_TC_BODY(create_race_and_short_write, tc)
{
	struct smp_bond_db db;
	int dirfd;

	(void)unlink("bonds.key");
	db_init(&db, &dirfd);
	inject_create_race = 1;
	ATF_CHECK_EQ(0, smp_bond_db_save(&db));
	ATF_CHECK_EQ(0, inject_create_race);
	ATF_CHECK(db.has_bond_secret);
	{
		uint8_t expected[BLUED_TEST_BOND_SECRET_SIZE];
		memset(expected, BLUED_TEST_SECRET_RACING_BYTE, sizeof(expected));
		ATF_CHECK(memcmp(expected, db.bond_secret, sizeof(expected)) == 0);
	}
	db_fini(&db, dirfd);

	/* Force a fresh create so the wrapped write is necessarily reached. */
	ATF_REQUIRE_EQ(-1, access("bonds.key", F_OK));
	db_init(&db, &dirfd);
	inject_short_write = true;
	ATF_CHECK_EQ(0, smp_bond_db_save(&db));
	ATF_CHECK(!inject_short_write);
	{
		struct stat st;
		ATF_REQUIRE_EQ(0, stat("bonds.key", &st));
		ATF_CHECK_EQ(BLUED_TEST_BOND_SECRET_SIZE, st.st_size);
	}
	db_fini(&db, dirfd);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, create_and_cache);
	ATF_TP_ADD_TC(tp, load_existing);
	ATF_TP_ADD_TC(tp, reject_truncated_or_nonregular);
	ATF_TP_ADD_TC(tp, create_race_and_short_write);
	return (atf_no_error());
}
