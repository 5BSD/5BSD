/* SPDX-License-Identifier: BSD-2-Clause */
/* Test-only NFSv3 READDIR client for the native kernel-server cookie path. */
#ifndef NFS_COOKIE_CLIENT_HH
#define NFS_COOKIE_CLIENT_HH

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rpc/rpc.h>
#include <unistd.h>

#include <array>
#include <string>
#include <vector>

namespace nfs_cookie {
struct Entry {
	uint64_t fileid;
	std::string name;
	uint64_t cookie;
};
struct Reply {
	u_int status = 0;
	std::array<char, 8> verifier{};
	std::vector<Entry> entries;
	bool eof = false;
};
struct Request {
	fhandle_t handle{};
	uint64_t cookie = 0;
	std::array<char, 8> verifier{};
	u_int count = 512;
};

inline bool_t
boolean(XDR *xdr, u_int &value)
{
	return (xdr_u_int(xdr, &value) && value <= 1);
}

inline bool_t
request(XDR *xdr, void *arg)
{
	auto &r = *static_cast<Request *>(arg);
	u_int length = sizeof(r.handle);
	static_assert(sizeof(fhandle_t) <= 64, "NFSv3 file handle size");
	return (xdr->x_op == XDR_ENCODE && xdr_u_int(xdr, &length) &&
	    xdr_opaque(xdr, reinterpret_cast<char *>(&r.handle), length) &&
	    xdr_u_int64_t(xdr, &r.cookie) &&
	    xdr_opaque(xdr, r.verifier.data(), r.verifier.size()) &&
	    xdr_u_int(xdr, &r.count));
}

inline bool_t
reply(XDR *xdr, void *arg)
{
	auto &r = *static_cast<Reply *>(arg);
	if (xdr->x_op == XDR_FREE)
		return (TRUE); /* C++ owns the decoded storage. */
	if (xdr->x_op != XDR_DECODE)
		return (FALSE);
	r = Reply{};
	u_int present = 0;
	char attributes[84]; /* NFSX_V3FATTR, not a native struct stat. */
	if (!xdr_u_int(xdr, &r.status) || !boolean(xdr, present) ||
	    (present && !xdr_opaque(xdr, attributes, sizeof(attributes))))
		return (FALSE);
	if (r.status != 0)
		return (TRUE);
	if (!xdr_opaque(xdr, r.verifier.data(), r.verifier.size()))
		return (FALSE);
	for (;;) {
		if (!boolean(xdr, present))
			return (FALSE);
		if (!present)
			break;
		/* Bound malformed lists even if a peer ignores request.count. */
		if (r.entries.size() >= 256)
			return (FALSE);
		Entry entry{};
		u_int length = 0;
		if (!xdr_u_int64_t(xdr, &entry.fileid) ||
		    !xdr_u_int(xdr, &length) || length == 0 || length > 255)
			return (FALSE);
		entry.name.resize(length);
		if (!xdr_opaque(xdr, &entry.name[0], length) ||
		    entry.name.find('\0') != std::string::npos ||
		    entry.name.find('/') != std::string::npos ||
		    !xdr_u_int64_t(xdr, &entry.cookie))
			return (FALSE);
		r.entries.push_back(entry);
	}
	if (!boolean(xdr, present))
		return (FALSE);
	r.eof = present != 0;
	return (TRUE);
}

inline bool_t nothing(XDR *, void *) { return (TRUE); }

class Client {
	CLIENT *client = nullptr;
	int socket_fd = -1;
public:
	Client() = default;
	Client(const Client &) = delete;
	Client &operator=(const Client &) = delete;
	~Client() {
		if (client != nullptr) {
			if (client->cl_auth != nullptr)
				auth_destroy(client->cl_auth);
			clnt_destroy(client);
		}
		if (socket_fd >= 0)
			close(socket_fd);
	}
	bool connect() {
		if (socket_fd >= 0)
			return (false);
		socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (socket_fd < 0)
			return (false);
		sockaddr_in local{};
		local.sin_len = sizeof(local);
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bindresvport(socket_fd, &local) != 0)
			return (false);
		sockaddr_in server = local;
		server.sin_port = htons(2049);
		timeval retry{0, 200000};
		client = clntudp_create(&server, 100003, 3, retry, &socket_fd);
		if (client == nullptr)
			return (false);
		client->cl_auth = authunix_create_default();
		return (client->cl_auth != nullptr);
	}
	enum clnt_stat ready() {
		timeval timeout{0, 200000};
		return (clnt_call(client, 0, nothing, nullptr, nothing, nullptr,
		    timeout));
	}
	enum clnt_stat readdir(Request &req, Reply &out) {
		timeval timeout{5, 0};
		return (clnt_call(client, 16, request, &req, reply, &out, timeout));
	}
};
} /* namespace nfs_cookie */
#endif
