/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Model and property tests for daemon header components, compiled from the
 * unmodified headers and linked with the actual daemon objects:
 *   - collector_owner_registry (dtraced_collector_owner.h): 20,000 random
 *     operations against a std::map model with descriptor accounting, the
 *     4,096-owner bound, round-robin batch fairness and injected allocation,
 *     duplication and close failures;
 *   - hypertrace_elf_append (dtraced_elf.h): fragment assembly against an
 *     independent reassembly model, including every invalid transition;
 *   - derived-program identity (dtraced_derived.h): header round trips and
 *     an independently built HDERIV1 preimage;
 *   - HSA1 release attestations (dtraced_release_attestation.h): real Ed25519
 *     signatures, every single-byte mutation rejected, argument checks.
 */
#include <sys/resource.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <map>
#include <new>
#include <random>
#include <set>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_collector_owner.h"
#include "dtraced_derived.h"
#include "dtraced_elf.h"
#include "dtraced_release_attestation.h"

using namespace dtraced;

static pthread_t main_thread;
static int fail_new = -1;	/* fail the n-th allocation on the main thread */
extern "C" void *__real__Znwm(size_t);
extern "C" void *
__wrap__Znwm(size_t n)
{
	if (pthread_equal(pthread_self(), main_thread) && fail_new >= 0 &&
	    fail_new-- == 0)
		throw std::bad_alloc();
	return (__real__Znwm(n));
}
static int fail_close_fd = -2;
extern "C" int __real_close(int);
extern "C" int
__wrap_close(int fd)
{
	int r = __real_close(fd);
	if (fd == fail_close_fd) {
		fail_close_fd = -2;
		errno = EIO;
		return (-1);
	}
	return (r);
}

static int
open_fds()
{
	int n = 0;
	for (int fd = 0; fd < 8192; ++fd)
		if (fcntl(fd, F_GETFD) != -1)
			++n;
	return (n);
}

static std::mt19937_64 rng(0x5bd5);

static collector_owner_key
key_of(unsigned i)
{
	std::array<uint8_t, 16> session{}, birth{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> handle{};
	session[0] = (uint8_t)i;
	session[1] = (uint8_t)(i >> 8);
	birth[2] = 7;
	program[3] = 9;
	handle[4] = 11;
	return (collector_owner_identity(session, birth, 1000 + i, 2000 + i,
	    program, handle));
}

static void
test_owner_identity()
{
	std::array<uint8_t, 16> session{}, birth{};
	std::array<uint8_t, 32> program{};
	std::array<uint8_t, 24> handle{};
	for (unsigned i = 0; i < 16; ++i) {
		session[i] = (uint8_t)(i + 1);
		birth[i] = (uint8_t)(i + 0x20);
	}
	for (unsigned i = 0; i < 32; ++i)
		program[i] = (uint8_t)(i + 0x40);
	for (unsigned i = 0; i < 24; ++i)
		handle[i] = (uint8_t)(i + 0x80);
	collector_owner_key k = collector_owner_identity(session, birth,
	    0x01020304, 0x0a0b0c0d, program, handle);
	CHECK(memcmp(k.data(), session.data(), 16) == 0 &&
	    memcmp(k.data() + 16, birth.data(), 16) == 0 &&
	    k[32] == 4 && k[35] == 1 && k[36] == 0x0d && k[39] == 0x0a &&
	    memcmp(k.data() + 40, program.data(), 32) == 0 &&
	    memcmp(k.data() + 72, handle.data(), 24) == 0);
}

static void
test_owner_registry()
{
	int baseline = open_fds();
	int devnull = open("/dev/null", O_RDONLY);
	{
		collector_owner_registry r;
		std::map<collector_owner_key, bool> model;
		collector_owner_key cursor{};
		CHECK(r.retain(key_of(1), -1) == -1 && errno == EBADF);
		std::array<collector_owner_key, 32> batch;
		CHECK(r.batch_after(cursor, batch) == 0);
		CHECK(r.exited(key_of(1)) == -1 && errno == EAGAIN);
		CHECK(r.reaper_empty(key_of(1)) == -1 && errno == EAGAIN);
		for (int op = 0; op < 20000; ++op) {
			unsigned k = (unsigned)(rng() % 64);
			switch (rng() % 4) {
			case 0:
				CHECK(r.retain(key_of(k), devnull) == 0);
				model[key_of(k)] = true;
				break;
			case 1: {
				bool had = model.erase(key_of(k)) != 0;
				CHECK(r.release_after_durable_exit(key_of(k)) == 0);
				(void)had;
				break;
			}
			case 2:
				CHECK(r.retained(key_of(k)) == (model.count(key_of(k)) != 0));
				break;
			default: {
				/* /dev/null is not a process descriptor: the
				 * registry forwards the error, never proof */
				if (model.count(key_of(k)) != 0) {
					CHECK(r.exited(key_of(k)) == -1);
				}
				break;
			}
			}
			/* descriptor accounting: one dup per retained owner */
			if (op % 997 == 0)
				CHECK(open_fds() == baseline + 1 + (int)model.size());
		}
		/* batches visit every owner exactly once per round, in order,
		 * wrapping after the last key */
		std::set<collector_owner_key> seen;
		size_t total = model.size(), visited = 0;
		cursor = {};
		while (visited < total) {
			size_t n = r.batch_after(cursor, batch);
			CHECK(n == std::min<size_t>(32, total));
			for (size_t i = 0; i < n && visited < total; ++i, ++visited)
				CHECK(seen.insert(batch[i]).second);
			CHECK(cursor == batch[n - 1]);
		}
		CHECK(seen.size() == total);
		for (const auto &[key, present] : model)
			CHECK(seen.count(key) == 1 && present);
		/* a removed cursor remains a valid ordering point */
		if (!model.empty()) {
			collector_owner_key first = model.begin()->first;
			CHECK(r.release_after_durable_exit(first) == 0);
			cursor = first;
			size_t n = r.batch_after(cursor, batch);
			CHECK(n >= 1 && batch[0] != first);
		}
	}
	CHECK(open_fds() == baseline + 1);	/* destructor closed every dup */
	{
		/* the bound refuses new owners instead of evicting evidence */
		collector_owner_registry r;
		for (unsigned i = 0; i < 4096; ++i)
			CHECK(r.retain(key_of(i), devnull) == 0);
		CHECK(r.retain(key_of(5000), devnull) == -1 && errno == ENOSPC);
		CHECK(r.retain(key_of(7), devnull) == 0);	/* idempotent */
		std::array<collector_owner_key, 32> batch;
		collector_owner_key cursor{};
		CHECK(r.batch_after(cursor, batch) == 32);
	}
	CHECK(open_fds() == baseline + 1);
	{
		collector_owner_registry r;
		/* allocation failure keeps no descriptor */
		fail_new = 0;
		CHECK(r.retain(key_of(1), devnull) == -1 && errno == ENOMEM);
		fail_new = -1;
		CHECK(!r.retained(key_of(1)) && open_fds() == baseline + 1);
		/* duplication failure: no free descriptor below the limit */
		auto lowest_free = [] {
			int probe = open("/dev/null", O_RDONLY);
			close(probe);
			return (probe);
		};
		struct rlimit old, low;
		CHECK(getrlimit(RLIMIT_NOFILE, &old) == 0);
		low = old;
		low.rlim_cur = (rlim_t)lowest_free();
		CHECK(setrlimit(RLIMIT_NOFILE, &low) == 0);
		CHECK(r.retain(key_of(2), devnull) == -1 && errno == EMFILE);
		CHECK(setrlimit(RLIMIT_NOFILE, &old) == 0);
		CHECK(!r.retained(key_of(2)));
		/* a close failure on release is reported once, never retried */
		int dup_fd = lowest_free();
		CHECK(r.retain(key_of(3), devnull) == 0);
		CHECK(fcntl(dup_fd, F_GETFD) != -1);
		fail_close_fd = dup_fd;
		CHECK(r.release_after_durable_exit(key_of(3)) == -1 && errno == EIO);
		CHECK(!r.retained(key_of(3)) && fcntl(dup_fd, F_GETFD) == -1);
		CHECK(r.release_after_durable_exit(key_of(3)) == 0);
	}
	close(devnull);
	CHECK(open_fds() == baseline);
}

/* ---- ELF fragment assembly ---- */
struct elf_model {
	bool active = false;
	size_t total = 0, received = 0;
	uint32_t identifier = 0;
	std::vector<unsigned char> data;
	/* returns 0 accept, EINVAL reject; sets complete */
	int append(uint32_t id, size_t tot, const unsigned char *d, size_t len,
	    int more, int &complete)
	{
		complete = 0;
		auto reset = [&] { *this = elf_model{}; return (EINVAL); };
		if (d == nullptr || tot == 0 || tot > HYPERTRACE_ELF_MAX || len == 0 ||
		    len > tot || (more != 0 && more != 1))
			return (reset());
		if (active && (total != tot || identifier != id))
			return (reset());
		size_t have = active ? received : 0;
		if (len > tot - have || (more == 0 && len != tot - have) ||
		    (more != 0 && len == tot - have))
			return (reset());
		if (!active) {
			active = true;
			total = tot;
			identifier = id;
		}
		data.insert(data.end(), d, d + len);
		received += len;
		complete = more == 0;
		return (0);
	}
};

static void
test_elf_assembly()
{
	unsigned char buf[64];
	for (unsigned i = 0; i < sizeof(buf); ++i)
		buf[i] = (unsigned char)(i * 7);
	for (int trial = 0; trial < 20000; ++trial) {
		hypertrace_elf s{};
		elf_model m;
		int steps = 1 + (int)(rng() % 6);
		for (int step = 0; step < steps; ++step) {
			uint32_t id = (uint32_t)(rng() % 3);
			size_t tot = rng() % 8 == 0 ? (rng() % 2 ? 0 : HYPERTRACE_ELF_MAX + 1) :
			    1 + rng() % 40;
			if (m.active && rng() % 4 != 0) {
				tot = m.total;
				id = m.identifier;
			}
			size_t len = rng() % 10 == 0 ? 0 : 1 + rng() % 24;
			int more = (int)(rng() % 7 == 0 ? 2 : rng() % 2);
			if (m.active && rng() % 3 == 0) {
				len = m.total - m.received;
				more = 0;
			}
			const unsigned char *d = rng() % 20 == 0 ? nullptr : buf;
			if (len > sizeof(buf))
				len = sizeof(buf);
			int mc = -1, sc = -1;
			int me = m.append(id, tot, d, len, more, mc);
			int se = hypertrace_elf_append(&s, id, tot, d, len, more, &sc);
			CHECK(me == se && mc == sc);
			CHECK((s.data != nullptr) == m.active);
			if (m.active)
				CHECK(s.total == m.total && s.received == m.received &&
				    s.identifier == m.identifier &&
				    memcmp(s.data, m.data.data(), m.received) == 0);
			if (sc == 1) {
				hypertrace_elf_reset(&s);
				m = elf_model{};
			}
		}
		hypertrace_elf_reset(&s);
		CHECK(s.data == nullptr && s.total == 0 && s.received == 0);
	}
}

/* ---- derived program identity ---- */
static void
test_derived()
{
	dtraced_derived_parent_t p{};
	p.consumer_session[0] = 1;
	p.delivery_id = 0x0102030405060708ull;
	p.vmid = 0x0a0b;
	p.epoch = 0x1112131415161718ull;
	p.program_id[0] = 2;
	p.source_id[0] = 3;
	CHECK(dtraced_derived_parent_valid(&p));
	CHECK(!dtraced_derived_parent_valid(nullptr));
	using edit_t = void (*)(dtraced_derived_parent_t &);
	const edit_t invalid[] = {
		[](dtraced_derived_parent_t &x) { x.delivery_id = 0; },
		[](dtraced_derived_parent_t &x) { x.vmid = 0; },
		[](dtraced_derived_parent_t &x) { x.epoch = 0; },
		[](dtraced_derived_parent_t &x) { x.consumer_session[0] = 0; },
		[](dtraced_derived_parent_t &x) { x.program_id[0] = 0; },
		[](dtraced_derived_parent_t &x) { x.source_id[0] = 0; },
	};
	dtraced_hdr_t h{};
	for (edit_t e : invalid) {
		dtraced_derived_parent_t q = p;
		e(q);
		CHECK(!dtraced_derived_parent_valid(&q));
		CHECK(dtraced_derived_parent_to_header(&h, &q) == -1 && errno == EINVAL);
		uint8_t id[16], digest[32] = {1};
		CHECK(dtraced_derived_program_id_from_digest(&q, digest, id) == -1 &&
		    errno == EINVAL);
	}
	CHECK(dtraced_derived_parent_to_header(nullptr, &p) == -1 && errno == EINVAL);
	memset(&h, 0x77, sizeof(h));
	CHECK(dtraced_derived_parent_to_header(&h, &p) == 0);
	CHECK(h.installed.delivery_id == p.delivery_id && h.installed.vmid == p.vmid &&
	    h.installed.epoch == p.epoch &&
	    memcmp(h.installed.name, p.consumer_session, 16) == 0);
	for (size_t i = 16; i < sizeof(h.installed.name); ++i)
		CHECK(h.installed.name[i] == 0);
	dtraced_derived_parent_t back{};
	CHECK(dtraced_derived_parent_from_header(&back, &h) == 0 &&
	    memcmp(&back, &p, sizeof(p)) == 0);
	CHECK(dtraced_derived_parent_from_header(nullptr, &h) == -1 && errno == EPROTO);
	CHECK(dtraced_derived_parent_from_header(&back, nullptr) == -1 && errno == EPROTO);
	h.installed.name[40] = 1;	/* text beyond the session */
	CHECK(dtraced_derived_parent_from_header(&back, &h) == -1 && errno == EPROTO);
	h.installed.name[40] = 0;
	h.installed.delivery_id = 0;	/* decodes to an invalid parent */
	CHECK(dtraced_derived_parent_from_header(&back, &h) == -1 && errno == EPROTO);
	/* independent HDERIV1 preimage */
	const unsigned char payload[] = "\177ELFpayload";
	uint8_t pd[32], pre[106] = {'H', 'D', 'E', 'R', 'I', 'V', '1', 0}, want[32];
	SHA256(payload, sizeof(payload), pd);
	memcpy(pre + 8, p.consumer_session, 16);
	for (int i = 0; i < 8; ++i) {
		pre[24 + i] = (uint8_t)(p.delivery_id >> (8 * i));
		pre[34 + i] = (uint8_t)(p.epoch >> (8 * i));
	}
	pre[32] = (uint8_t)p.vmid;
	pre[33] = (uint8_t)(p.vmid >> 8);
	memcpy(pre + 42, p.program_id, 16);
	memcpy(pre + 58, p.source_id, 16);
	memcpy(pre + 74, pd, 32);
	SHA256(pre, sizeof(pre), want);
	uint8_t id[16];
	CHECK(dtraced_derived_program_id(&p, payload, sizeof(payload), id) == 0 &&
	    memcmp(id, want, 16) == 0);
	CHECK(dtraced_derived_program_id(&p, nullptr, 4, id) == -1 && errno == EINVAL);
	CHECK(dtraced_derived_program_id(&p, payload, 0, id) == -1 && errno == EINVAL);
	CHECK(dtraced_derived_program_id_from_digest(&p, nullptr, id) == -1 &&
	    errno == EINVAL);
	CHECK(dtraced_derived_program_id_from_digest(&p, pd, nullptr) == -1 &&
	    errno == EINVAL);
}

/* ---- HSA1 release attestations ---- */
static EVP_PKEY *
ed25519()
{
	EVP_PKEY *key = nullptr;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
	CHECK(ctx != nullptr && EVP_PKEY_keygen_init(ctx) == 1 &&
	    EVP_PKEY_keygen(ctx, &key) == 1);
	EVP_PKEY_CTX_free(ctx);
	return (key);
}

static void
test_release_attestation()
{
	uint8_t hsl[DTRACED_RELEASE_HSL_SIZE];
	for (unsigned i = 0; i < 156; ++i)
		hsl[i] = (uint8_t)(i * 3);
	memcpy(hsl, "HSL1", 4);
	SHA256(hsl, 156, hsl + 156);
	CHECK(dtraced_release_hsl_valid(hsl));
	CHECK(!dtraced_release_hsl_valid(nullptr) && errno == EPROTO);
	for (unsigned pos = 0; pos < sizeof(hsl); ++pos) {
		hsl[pos] ^= 1;
		CHECK(!dtraced_release_hsl_valid(hsl) && errno == EPROTO);
		hsl[pos] ^= 1;
	}
	EVP_PKEY *source = ed25519(), *destination = ed25519();
	uint8_t spub[32], dpub[32];
	size_t n = 32;
	CHECK(EVP_PKEY_get_raw_public_key(source, spub, &n) == 1);
	n = 32;
	CHECK(EVP_PKEY_get_raw_public_key(destination, dpub, &n) == 1);
	uint8_t wire[DTRACED_RELEASE_ATTESTED_SIZE];
	CHECK(dtraced_release_attestation_sign(source, dpub, hsl, wire));
	/* independent layout */
	CHECK(memcmp(wire, "HSA1", 4) == 0 && wire[4] == 1 && wire[5] == 0 &&
	    wire[6] == 0 && wire[7] == 0 && memcmp(wire + 8, spub, 32) == 0 &&
	    memcmp(wire + 40, dpub, 32) == 0 && memcmp(wire + 72, hsl, 188) == 0);
	CHECK(dtraced_release_attestation_verify(spub, dpub, hsl, wire));
	for (unsigned pos = 0; pos < sizeof(wire); ++pos) {
		wire[pos] ^= 0x10;
		CHECK(!dtraced_release_attestation_verify(spub, dpub, hsl, wire) &&
		    errno == EPROTO);
		wire[pos] ^= 0x10;
	}
	/* the verifier's own key material and expected witness are binding */
	CHECK(!dtraced_release_attestation_verify(dpub, dpub, hsl, wire));
	CHECK(!dtraced_release_attestation_verify(spub, spub, hsl, wire));
	uint8_t other[DTRACED_RELEASE_HSL_SIZE];
	memcpy(other, hsl, sizeof(other));
	other[10] ^= 1;
	SHA256(other, 156, other + 156);
	CHECK(!dtraced_release_attestation_verify(spub, dpub, other, wire));
	other[0] = 'X';
	CHECK(!dtraced_release_attestation_verify(spub, dpub, other, wire));
	CHECK(!dtraced_release_attestation_verify(nullptr, dpub, hsl, wire));
	CHECK(!dtraced_release_attestation_verify(spub, nullptr, hsl, wire));
	CHECK(!dtraced_release_attestation_verify(spub, dpub, hsl, nullptr));
	/* a public key that is not a curve point cannot verify */
	uint8_t junk[32];
	memset(junk, 0xff, sizeof(junk));
	memcpy(wire + 8, junk, 32);
	CHECK(!dtraced_release_attestation_verify(junk, dpub, hsl, wire));
	/* signing preconditions */
	uint8_t zero[32] = {};
	CHECK(!dtraced_release_attestation_sign(nullptr, dpub, hsl, wire) && errno == EINVAL);
	CHECK(!dtraced_release_attestation_sign(source, nullptr, hsl, wire) && errno == EINVAL);
	CHECK(!dtraced_release_attestation_sign(source, zero, hsl, wire) && errno == EINVAL);
	CHECK(!dtraced_release_attestation_sign(source, dpub, hsl, nullptr) && errno == EINVAL);
	CHECK(!dtraced_release_attestation_sign(source, dpub, other, wire) && errno == EINVAL);
	EVP_PKEY_CTX *rctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
	EVP_PKEY *x = nullptr;
	CHECK(rctx && EVP_PKEY_keygen_init(rctx) == 1 && EVP_PKEY_keygen(rctx, &x) == 1);
	EVP_PKEY_CTX_free(rctx);
	CHECK(!dtraced_release_attestation_sign(x, dpub, hsl, wire) && errno == EINVAL);
	/* a public-only Ed25519 key cannot sign */
	EVP_PKEY *public_only = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
	    nullptr, spub, 32);
	CHECK(!dtraced_release_attestation_sign(public_only, dpub, hsl, wire) &&
	    errno == EIO);
	EVP_PKEY_free(public_only);
	EVP_PKEY_free(x);
	EVP_PKEY_free(source);
	EVP_PKEY_free(destination);
}

int
main()
{
	alarm(200);
	main_thread = pthread_self();
	test_owner_identity();
	test_owner_registry();
	test_elf_assembly();
	test_derived();
	test_release_attestation();
	printf("header-props: %u checks passed\n", harness_checks);
	return (0);
}
