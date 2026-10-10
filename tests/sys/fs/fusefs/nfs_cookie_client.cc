/* SPDX-License-Identifier: BSD-2-Clause */
/* Wire decoder checks: no mounts, servers or root privileges required. */
#include "nfs_cookie_client.hh"
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define CHECK(x) do { if (!(x)) { \
	fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #x); \
	return (1); } } while (0)

static void
word(std::vector<char> &wire, uint32_t value)
{
	value = htonl(value);
	const char *p = reinterpret_cast<const char *>(&value);
	wire.insert(wire.end(), p, p + sizeof(value));
}
static std::vector<char>
record()
{
	std::vector<char> wire;
	word(wire, 0); /* NFS_OK */
	word(wire, 0); /* no post-operation attributes */
	word(wire, 0x11223344); word(wire, 0x55667788); /* verifier */
	word(wire, 1); /* entry follows */
	word(wire, 1); word(wire, 42); /* 64-bit fileid */
	word(wire, 3); word(wire, 0x61626300); /* "abc" + padding */
	word(wire, 2); word(wire, 107); /* 64-bit nonconsecutive cookie */
	word(wire, 0); word(wire, 1); /* list end, EOF */
	return (wire);
}
static bool
decode(std::vector<char> &wire, nfs_cookie::Reply &out)
{
	XDR xdr;
	xdrmem_create(&xdr, wire.data(), wire.size(), XDR_DECODE);
	bool ok = nfs_cookie::reply(&xdr, &out) && xdr_getpos(&xdr) == wire.size();
	xdr_destroy(&xdr);
	return (ok);
}
int
main()
{
	auto good = record();
	nfs_cookie::Reply out;
	CHECK(decode(good, out));
	CHECK(out.status == 0 && out.eof && out.entries.size() == 1);
	CHECK(out.entries[0].fileid == (uint64_t(1) << 32) + 42);
	CHECK(out.entries[0].cookie == (uint64_t(2) << 32) + 107);
	CHECK(out.entries[0].name == "abc");
	CHECK(static_cast<unsigned char>(out.verifier[0]) == 0x11);
	auto with_attributes = good;
	with_attributes.insert(with_attributes.begin() + 8, 84, 0);
	uint32_t yes = htonl(1);
	memcpy(with_attributes.data() + 4, &yes, sizeof(yes));
	CHECK(decode(with_attributes, out) && out.entries.size() == 1);
	for (size_t n = 8; n < 92; n++) {
		std::vector<char> truncated(with_attributes.begin(),
		    with_attributes.begin() + n);
		CHECK(!decode(truncated, out));
	}
	auto too_many = std::vector<char>(good.begin(), good.begin() + 16);
	for (unsigned i = 0; i < 257; i++)
		too_many.insert(too_many.end(), good.begin() + 16, good.begin() + 44);
	word(too_many, 0); word(too_many, 1);
	CHECK(!decode(too_many, out));
	for (size_t n = 0; n < good.size(); n++) {
		std::vector<char> truncated(good.begin(), good.begin() + n);
		CHECK(!decode(truncated, out));
	}
	for (uint32_t size : {0u, 256u, UINT32_MAX}) {
		auto bad = good;
		uint32_t value = htonl(size);
		memcpy(bad.data() + 28, &value, sizeof(value));
		CHECK(!decode(bad, out));
	}
	for (size_t offset : {size_t(4), size_t(16), size_t(48)}) {
		auto bad = good;
		uint32_t value = htonl(2);
		memcpy(bad.data() + offset, &value, sizeof(value));
		CHECK(!decode(bad, out));
	}
	for (char invalid : {'\0', '/'}) {
		auto bad = good;
		bad[32] = invalid;
		CHECK(!decode(bad, out));
	}
	std::vector<char> error;
	word(error, 13); word(error, 0); /* NFS access error, no attributes */
	CHECK(decode(error, out) && out.status == 13 && out.entries.empty());
	puts("NFS_COOKIE_DECODER PASS");
	return (0);
}
