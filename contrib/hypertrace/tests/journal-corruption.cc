/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Recovery from damaged delivery journals, using the actual daemon
 * dir::list_deliveries / delivery_status readers.
 *
 * Records are written by an independent encoder built from the documented
 * HTD2/HTD3/HTD4/HTD5 layouts (fixed offsets, little-endian fields, SHA-256
 * trailer). Oracles:
 *   - a well-formed record is listed with exactly the encoded fields and the
 *     phase named by its file;
 *   - a record that is well-formed on disk but violates the documented
 *     scope/version/ownership rules is refused with EPROTO;
 *   - every single-byte change, truncation, extension, file-name damage,
 *     duplicate phase or non-regular entry makes recovery fail closed
 *     (EPROTO or a file-system error), never return a different record;
 *   - unrelated names are ignored.
 */
#include <sys/stat.h>
#include <sys/hypertrace.h>
#include <openssl/sha.h>
#include <memory>
#include <string>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_directory.h"
#include "dtraced_state.h"

using namespace dtraced;

struct rec {
	int version = 4;	/* 2..5 */
	uint8_t session[16] = {1};
	uint64_t delivery = 17;
	uint16_t vmid = 42;
	uint64_t epoch = 99;
	uint8_t program[16] = {2};
	uint8_t source[16] = {3};
	uint32_t uid = 0, pid = 0;
	uint8_t scope = 1;
	uint8_t digest[32] = {4};
	uint8_t token[16] = {};
	uint8_t source_session[16] = {};
	uint16_t payload_vmid = 0;
	uint64_t payload_epoch = 0;
};

static void
le(std::vector<uint8_t> &b, size_t off, uint64_t v, unsigned n)
{
	for (unsigned i = 0; i < n; ++i)
		b[off + i] = (uint8_t)(v >> (8 * i));
}

/* Independent on-disk encoder. */
static std::vector<uint8_t>
encode(const rec &r)
{
	size_t body = r.version == 2 ? 78 : r.version == 3 ? 79 :
	    r.version == 4 ? 111 : 153;
	std::vector<uint8_t> b(body + 32, 0);
	memcpy(b.data(), r.version == 2 ? "HTD2" : r.version == 3 ? "HTD3" :
	    r.version == 4 ? "HTD4" : "HTD5", 4);
	memcpy(&b[4], r.session, 16);
	le(b, 20, r.delivery, 8);
	le(b, 28, r.vmid, 2);
	le(b, 30, r.epoch, 8);
	memcpy(&b[38], r.program, 16);
	memcpy(&b[54], r.source, 16);
	le(b, 70, r.uid, 4);
	le(b, 74, r.pid, 4);
	if (r.version >= 3)
		b[78] = r.scope;
	if (r.version >= 4)
		memcpy(&b[79], r.digest, 32);
	if (r.version == 5) {
		memcpy(&b[111], r.token, 16);
		memcpy(&b[127], r.source_session, 16);
		le(b, 143, r.payload_vmid, 2);
		le(b, 145, r.payload_epoch, 8);
	}
	SHA256(b.data(), body, &b[body]);
	return (b);
}

static std::string
name_of(const rec &r, char phase)
{
	char n[80];
	char *p = n + snprintf(n, sizeof(n), ".delivery.");
	for (uint8_t byte : r.session)
		p += snprintf(p, 3, "%02x", byte);
	snprintf(p, sizeof(n) - (size_t)(p - n), ".%016jx.%c",
	    (uintmax_t)r.delivery, phase);
	return (n);
}

struct journal {
	temp_tree tree{"journal-corruption"};
	std::string path;
	std::unique_ptr<dir> d;
	journal() : path(tree.sub("j")) { d = std::make_unique<dir>(path.c_str(), nullptr); }
	void put(const std::string &name, const std::vector<uint8_t> &bytes)
	{
		int fd = openat(d->dirfd, name.c_str(),
		    O_WRONLY | O_CREAT | O_TRUNC, 0600);
		CHECK(fd >= 0);
		CHECK(write(fd, bytes.data(), bytes.size()) == (ssize_t)bytes.size());
		close(fd);
	}
	void remove(const std::string &name) { unlinkat(d->dirfd, name.c_str(), 0); }
};

static bool
equal(const durable_delivery &d, const rec &r)
{
	int v = r.version == 2 ? 3 : r.version;
	return (memcmp(d.session_id.data(), r.session, 16) == 0 &&
	    d.delivery_id == r.delivery && d.vmid == r.vmid && d.epoch == r.epoch &&
	    memcmp(d.program_id.data(), r.program, 16) == 0 &&
	    memcmp(d.source_id.data(), r.source, 16) == 0 &&
	    d.peer_uid == r.uid && d.peer_pid == r.pid &&
	    d.scope == (r.version == 2 ? 0 : r.scope) && d.journal_version == v &&
	    (v < 4 || memcmp(d.payload_digest.data(), r.digest, 32) == 0) &&
	    (v < 5 || (memcmp(d.handoff_token.data(), r.token, 16) == 0 &&
	    memcmp(d.source_session.data(), r.source_session, 16) == 0 &&
	    d.payload_vmid == r.payload_vmid && d.payload_epoch == r.payload_epoch)));
}

static rec
guest_v4()
{
	return (rec{});
}

static rec
host(int version)
{
	rec r;
	r.version = version;
	r.scope = 0;
	r.uid = 1001;
	r.pid = 4321;
	if (version < 4)
		memset(r.digest, 0, 32);
	if (version == 5) {
		r.token[0] = 9;
		r.source_session[0] = 8;
		r.payload_vmid = 7;
		r.payload_epoch = 6;
	}
	return (r);
}

static void
test_valid_corpus()
{
	struct { rec r; char phase; } valid[] = {
		{guest_v4(), 'p'},
		{[] { rec r = guest_v4(); r.version = 3; memset(r.digest, 0, 32);
		    return r; }(), 'a'},
		{host(2), 'i'},
		{host(3), 'x'},
		{host(4), 't'},
		{host(5), 'p'},
		{[] { rec r = host(4); r.scope = 3; return r; }(), 'a'},
		{[] { rec r = host(5); r.scope = 3; return r; }(), 'a'},
		{[] { rec r = host(4); r.scope = 2; r.vmid = 0; r.epoch = 0;
		    return r; }(), 'p'},
		{[] { rec r = host(3); r.scope = 2; return r; }(), 'a'},
	};
	for (auto &v : valid) {
		journal j;
		j.put(name_of(v.r, v.phase), encode(v.r));
		j.put("elf.unrelated", {1, 2, 3});
		j.put(".kill-unrelated", {});
		std::vector<durable_delivery_state> out;
		CHECK(j.d->list_deliveries(out));
		CHECK(out.size() == 1 && equal(out[0].record, v.r) &&
		    (char)out[0].phase == v.phase);
		CHECK(j.d->delivery_status(out[0].record) == v.phase);
	}
	/* All records of one journal are listed, each exactly once. */
	journal j;
	std::vector<rec> many;
	for (unsigned i = 0; i < 40; ++i) {
		rec r = guest_v4();
		r.session[1] = (uint8_t)i;
		r.delivery = 100 + i;
		many.push_back(r);
		j.put(name_of(r, "paixt"[i % 5]), encode(r));
	}
	std::vector<durable_delivery_state> out;
	CHECK(j.d->list_deliveries(out) && out.size() == many.size());
	for (const auto &r : many) {
		unsigned matches = 0;
		for (const auto &e : out)
			matches += equal(e.record, r);
		CHECK(matches == 1);
	}
}

static void
expect_refused(journal &j, int expected_errno = EPROTO)
{
	std::vector<durable_delivery_state> out;
	errno = 0;
	CHECK(!j.d->list_deliveries(out));
	if (expected_errno != 0)
		CHECK(errno == expected_errno);
}

static void
test_rule_violations()
{
	using edit_t = void (*)(rec &);
	const edit_t invalid[] = {
		[](rec &r) { memset(r.program, 0, 16); },
		[](rec &r) { memset(r.source, 0, 16); },
		[](rec &r) { r.vmid = 0; },
		[](rec &r) { r.vmid = HYPERTRACE_MAX_VMS; },
		[](rec &r) { r.epoch = 0; },
		[](rec &r) { r.uid = 5; },		/* guest records have no peer */
		[](rec &r) { r.pid = 5; },
		[](rec &r) { memset(r.digest, 0, 32); },	/* HTD4 must be bound */
		[](rec &r) { r.scope = 4; },
		[](rec &r) { r.version = 5; r.token[0] = 1; r.source_session[0] = 2;
		    r.payload_vmid = 3; r.payload_epoch = 4; },	/* guest cannot migrate */
		[](rec &r) { r.scope = 3; r.version = 3; memset(r.digest, 0, 32);
		    r.uid = 1; r.pid = 10; },			/* ingest needs HTD4/5 */
		[](rec &r) { r.scope = 0; r.uid = UINT32_MAX; r.pid = 10; },
		[](rec &r) { r.scope = 0; r.pid = 1; },
		[](rec &r) { r.scope = 2; r.vmid = 0; r.epoch = 5; r.pid = 10; },
		[](rec &r) { r.scope = 0; r.version = 5; r.pid = 10; r.token[0] = 1;
		    r.source_session[0] = 1; r.session[0] = 1; r.payload_vmid = 3;
		    r.payload_epoch = 4; },			/* source == own session */
		[](rec &r) { r.scope = 0; r.version = 5; r.pid = 10; r.token[0] = 1;
		    r.source_session[0] = 2; r.payload_vmid = 0; r.payload_epoch = 4; },
		[](rec &r) { r.scope = 0; r.version = 5; r.pid = 10; r.token[0] = 1;
		    r.source_session[0] = 2; r.payload_vmid = 3; r.payload_epoch = 0; },
		[](rec &r) { r.scope = 0; r.version = 5; r.pid = 10;
		    r.source_session[0] = 2; r.payload_vmid = 3; r.payload_epoch = 4; },
	};
	for (edit_t edit : invalid) {
		rec r = guest_v4();
		edit(r);
		journal j;
		j.put(name_of(r, 'p'), encode(r));
		expect_refused(j);
	}
}

static void
test_damage()
{
	const rec samples[] = {guest_v4(), host(2), host(3), host(5)};
	for (const rec &r : samples) {
		const auto good = encode(r);
		const std::string name = name_of(r, 'a');
		/* every byte changed */
		for (size_t pos = 0; pos < good.size(); ++pos) {
			journal j;
			auto bad = good;
			bad[pos] ^= 0x01;
			j.put(name, bad);
			expect_refused(j);
		}
		/* every truncation and a one-byte extension */
		for (size_t len = 0; len <= good.size() + 1; ++len) {
			if (len == good.size())
				continue;
			journal j;
			auto bad = good;
			bad.resize(len, 0);
			j.put(name, bad);
			expect_refused(j);
		}
	}
	rec r = guest_v4();
	auto bytes = encode(r);
	std::string good = name_of(r, 'p');
	/* file-name damage */
	std::vector<std::string> names;
	names.push_back(good.substr(0, 60) + "q");		/* unknown phase */
	names.push_back(good + "p");				/* too long */
	names.push_back(good.substr(0, 60));			/* too short */
	{ std::string n = good; n[11] = 'A'; names.push_back(n); }	/* hex case */
	{ std::string n = good; n[12] = 'g'; names.push_back(n); }	/* session hex */
	{ std::string n = good; n[50] = 'z'; names.push_back(n); }	/* id hex */
	{ std::string n = good; n[42] = '-'; names.push_back(n); }
	{ std::string n = good; n[59] = '-'; names.push_back(n); }
	{ std::string n = good; n[58] = '2'; names.push_back(n); }	/* id mismatch */
	{ std::string n = good; n[13] = '1'; names.push_back(n); }	/* session mismatch */
	for (const auto &n : names) {
		journal j;
		j.put(n, bytes);
		expect_refused(j);
	}
	/* two phases for one key */
	{
		journal j;
		j.put(name_of(r, 'p'), bytes);
		j.put(name_of(r, 'a'), bytes);
		expect_refused(j);
		durable_delivery d{};
		d.session_id[0] = 1;
		d.delivery_id = 17;
		d.vmid = 42;
		d.epoch = 99;
		d.program_id[0] = 2;
		d.source_id[0] = 3;
		d.scope = 1;
		d.journal_version = 4;
		d.payload_digest[0] = 4;
		errno = 0;
		CHECK(j.d->delivery_status(d) == -1 && errno == EPROTO);
	}
	/* non-regular entries under a record name */
	{
		journal j;
		CHECK(mkdirat(j.d->dirfd, good.c_str(), 0700) == 0);
		expect_refused(j);
	}
	{
		journal j;
		CHECK(symlinkat("/etc/passwd", j.d->dirfd, good.c_str()) == 0);
		expect_refused(j, EMLINK);	/* FreeBSD O_NOFOLLOW */
	}
	{
		journal j;
		CHECK(mkfifoat(j.d->dirfd, good.c_str(), 0600) == 0);
		expect_refused(j);
	}
	/* a record the reader cannot open */
	{
		journal j;
		j.put(good, bytes);
		CHECK(fchmodat(j.d->dirfd, good.c_str(), 0, 0) == 0);
		expect_refused(j, EACCES);
	}
}

int
main()
{
	alarm(200);
	test_valid_corpus();
	test_rule_violations();
	test_damage();
	printf("journal-corruption: %u checks passed\n", harness_checks);
	return (0);
}
