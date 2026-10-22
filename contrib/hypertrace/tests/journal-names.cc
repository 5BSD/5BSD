/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Name-encoded journals (kills, kill ACKs, cleanups, revocation tombstones)
 * read back through the actual dir readers. Records are created with an
 * independent name builder from the documented formats:
 *   .kill.<vmid:4x>.<epoch:16x>.<pid:8x>.<source:32x>      (empty file)
 *   .killack.<same suffix>                                  (empty file)
 *   .cleanup.<vmid:4x>.<epoch:16x>.<token:16x>.<p|a|g>      (empty file)
 * Oracles: valid sets are listed exactly; any malformed name, non-empty or
 * non-regular record, or two phases for one cleanup token makes the reader
 * fail closed with EPROTO (never a partial or substituted list).
 */
#include <sys/stat.h>
#include <sys/hypertrace.h>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_directory.h"

using namespace dtraced;

static std::string
kill_suffix(unsigned vmid, unsigned long long epoch, unsigned pid,
    const uint8_t source[16])
{
	char b[80];
	int n = snprintf(b, sizeof(b), "%04x.%016llx.%08x.", vmid, epoch, pid);
	for (int i = 0; i < 16; ++i)
		n += snprintf(b + n, sizeof(b) - (size_t)n, "%02x", source[i]);
	return (b);
}

static std::string
cleanup_file(unsigned vmid, unsigned long long epoch, unsigned long long token,
    char phase)
{
	char b[64];
	snprintf(b, sizeof(b), ".cleanup.%04x.%016llx.%016llx.%c", vmid, epoch,
	    token, phase);
	return (b);
}

struct journal {
	temp_tree tree{"journal-names"};
	std::unique_ptr<dir> d;
	journal() { d = std::make_unique<dir>(tree.sub("j").c_str(), nullptr); }
	void touch(const std::string &name, const char *content = "")
	{
		int fd = openat(d->dirfd, name.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
		CHECK(fd >= 0);
		size_t n = strlen(content);
		CHECK(write(fd, content, n) == (ssize_t)n);
		close(fd);
	}
};

static void
test_kills()
{
	uint8_t s1[16] = {0x10, 0xab}, s2[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0xff};
	struct { unsigned vmid; unsigned long long epoch; unsigned pid; const uint8_t *s; }
	    valid[] = {{1, 1, 2, s1}, {1023, ~0ull, 0x7fffffff, s2}, {42, 99, 4242, s1}};
	{
		journal j;
		std::set<std::tuple<unsigned, unsigned long long, unsigned>> want;
		for (auto &v : valid) {
			j.touch(".kill." + kill_suffix(v.vmid, v.epoch, v.pid, v.s));
			want.insert({v.vmid, v.epoch, v.pid});
		}
		j.touch(".killack." + kill_suffix(42, 99, 4242, s1));
		j.touch(".kill-unrelated-but-not-a-record");	/* prefix ".kill-" */
		std::vector<durable_kill> got;
		CHECK(j.d->list_kills(got) && got.size() == 3);
		for (const auto &k : got) {
			CHECK(want.erase({k.vmid, k.epoch, (unsigned)k.pid}) == 1);
			const uint8_t *src = k.pid == 0x7fffffff ? s2 : s1;
			CHECK(memcmp(k.source_id.data(), src, 16) == 0);
		}
		durable_kill acked{4242, 42, 99, {}};
		memcpy(acked.source_id.data(), s1, 16);
		CHECK(j.d->kill_applied(acked) == 1);
		durable_kill unacked{2, 1, 1, {}};
		memcpy(unacked.source_id.data(), s1, 16);
		CHECK(j.d->kill_applied(unacked) == 0);
		durable_kill absent{5, 1, 1, {}};
		memcpy(absent.source_id.data(), s1, 16);
		errno = 0;
		CHECK(j.d->kill_applied(absent) == -1 && errno == ENOENT);
		/* an acknowledgment that is not an empty file is not proof */
		j.touch(".killack." + kill_suffix(1, 1, 2, s1), "x");
		CHECK(j.d->kill_applied(unacked) == -1 && errno == EPROTO);
		/* invalid record identities are refused before any lookup */
		durable_kill bad = acked;
		bad.pid = 1;
		CHECK(j.d->kill_applied(bad) == -1 && errno == EINVAL);
	}
	const std::string good = ".kill." + kill_suffix(42, 99, 4242, s1);
	std::vector<std::string> malformed = {
		".kill." + kill_suffix(0, 99, 4242, s1),		/* vmid 0 */
		".kill." + kill_suffix(1024, 99, 4242, s1),		/* vmid range */
		".kill." + kill_suffix(42, 0, 4242, s1),		/* epoch 0 */
		".kill." + kill_suffix(42, 99, 1, s1),			/* pid 1 */
		".kill." + kill_suffix(42, 99, 0x80000000u, s1),	/* pid > INT_MAX */
		".kill." + kill_suffix(42, 99, 4242, (const uint8_t[16]){}),	/* source 0 */
		good + "0",						/* long */
		good.substr(0, 68),					/* short */
	};
	{ std::string n = good; n[6] = 'G'; malformed.push_back(n); }	/* vmid hex */
	{ std::string n = good; n[12] = 'A'; malformed.push_back(n); }	/* epoch case */
	{ std::string n = good; n[30] = 'x'; malformed.push_back(n); }	/* pid hex */
	{ std::string n = good; n[40] = 'z'; malformed.push_back(n); }	/* source hex */
	{ std::string n = good; n[10] = '-'; malformed.push_back(n); }
	{ std::string n = good; n[27] = '-'; malformed.push_back(n); }
	{ std::string n = good; n[36] = '-'; malformed.push_back(n); }
	for (const auto &name : malformed) {
		journal j;
		j.touch(good);
		j.touch(name);
		std::vector<durable_kill> got;
		errno = 0;
		CHECK(!j.d->list_kills(got) && errno == EPROTO && got.empty());
	}
	{	/* a record that is not an empty regular file */
		journal j;
		j.touch(good, "payload");
		std::vector<durable_kill> got;
		CHECK(!j.d->list_kills(got) && errno == EPROTO);
	}
	{
		journal j;
		CHECK(mkdirat(j.d->dirfd, good.c_str(), 0700) == 0);
		std::vector<durable_kill> got;
		CHECK(!j.d->list_kills(got) && errno == EPROTO);
	}
	{
		journal j;
		CHECK(symlinkat("/dev/null", j.d->dirfd, good.c_str()) == 0);
		std::vector<durable_kill> got;
		CHECK(!j.d->list_kills(got) && errno == EPROTO);
	}
}

static void
test_cleanups()
{
	{
		journal j;
		j.touch(cleanup_file(1, 2, 3, 'p'));
		j.touch(cleanup_file(1, 2, 4, 'a'));
		j.touch(cleanup_file(1023, ~0ull, ~0ull, 'g'));
		j.touch(cleanup_file(7, 8, 9, 'p'));
		std::vector<durable_cleanup> pending;
		CHECK(j.d->list_pending_cleanups(pending) && pending.size() == 2);
		std::set<unsigned long long> tokens;
		for (const auto &c : pending)
			tokens.insert(c.delivery_id);
		CHECK(tokens == std::set<unsigned long long>({3, 9}));
		CHECK(j.d->cleanup_status({1, 2, 3}) == 'p');
		CHECK(j.d->cleanup_status({1, 2, 4}) == 'a');
		CHECK(j.d->cleanup_status({1023, ~0ull, ~0ull}) == 'g');
		CHECK(j.d->cleanup_status({1, 2, 5}) == 0);
		CHECK(j.d->cleanup_status({0, 2, 5}) == -1 && errno == EINVAL);
		/* two phases for one token is not a valid durable state */
		j.touch(cleanup_file(1, 2, 3, 'a'));
		CHECK(j.d->cleanup_status({1, 2, 3}) == -1 && errno == EPROTO);
		/* a phase file with content is not a valid record */
		j.touch(cleanup_file(1, 2, 4, 'a'), "x");
		CHECK(j.d->cleanup_status({1, 2, 4}) == -1 && errno == EPROTO);
	}
	const std::string good = cleanup_file(42, 99, 77, 'p');
	std::vector<std::string> malformed = {
		cleanup_file(0, 99, 77, 'p'), cleanup_file(1024, 99, 77, 'p'),
		cleanup_file(42, 0, 77, 'p'), cleanup_file(42, 99, 0, 'p'),
		good.substr(0, 48) + "x", good + "p", good.substr(0, 48),
	};
	{ std::string n = good; n[9] = 'Q'; malformed.push_back(n); }
	{ std::string n = good; n[20] = 'F'; malformed.push_back(n); }
	{ std::string n = good; n[40] = 'g'; malformed.push_back(n); }
	{ std::string n = good; n[13] = '_'; malformed.push_back(n); }
	{ std::string n = good; n[30] = '_'; malformed.push_back(n); }
	{ std::string n = good; n[47] = '_'; malformed.push_back(n); }
	for (const auto &name : malformed) {
		journal j;
		j.touch(good);
		j.touch(name);
		std::vector<durable_cleanup> got;
		errno = 0;
		CHECK(!j.d->list_pending_cleanups(got) && errno == EPROTO);
	}
	{
		journal j;
		j.touch(good, "y");
		std::vector<durable_cleanup> got;
		CHECK(!j.d->list_pending_cleanups(got) && errno == EPROTO);
	}
}

static void
test_tombstones()
{
	journal j;
	uint8_t src[16] = {0x5a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	CHECK(j.d->source_revoked(src) == 0);
	CHECK(j.d->revoke_source(src) && j.d->source_revoked(src) == 1);
	CHECK(j.d->revoke_source(src));	/* idempotent */
	uint8_t zero[16] = {};
	CHECK(j.d->source_revoked(zero) == -1 && errno == EINVAL);
	CHECK(!j.d->revoke_source(zero) && errno == EINVAL);
	/* the tombstone name encodes the source; content is not trusted */
	char name[41] = ".revoke.";
	for (int i = 0; i < 16; ++i)
		snprintf(name + 8 + 2 * i, 3, "%02x", src[i]);
	struct stat st;
	CHECK(fstatat(j.d->dirfd, name, &st, 0) == 0 && S_ISREG(st.st_mode));
	CHECK(unlinkat(j.d->dirfd, name, 0) == 0);
	CHECK(mkdirat(j.d->dirfd, name, 0700) == 0);
	errno = 0;
	CHECK(j.d->source_revoked(src) == -1);
}

int
main()
{
	alarm(120);
	test_kills();
	test_cleanups();
	test_tombstones();
	printf("journal-names: %u checks passed\n", harness_checks);
	return (0);
}
