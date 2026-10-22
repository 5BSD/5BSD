/* SPDX-License-Identifier: BSD-2-Clause */
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include "dtraced_release_keys.h"

static EVP_PKEY *
new_key(int type)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, nullptr);
	EVP_PKEY *key = nullptr;
	assert(ctx != nullptr && EVP_PKEY_keygen_init(ctx) == 1);
	assert(EVP_PKEY_keygen(ctx, &key) == 1);
	EVP_PKEY_CTX_free(ctx);
	return (key);
}

static void
write_key(const std::string &path, EVP_PKEY *key, bool private_key)
{
	int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(fd >= 0);
	FILE *file = fdopen(fd, "w");
	assert(file != nullptr);
	assert(private_key ? PEM_write_PrivateKey(file, key, nullptr,
	    nullptr, 0, nullptr, nullptr) == 1 :
	    PEM_write_PUBKEY(file, key) == 1);
	assert(fflush(file) == 0 && fsync(fd) == 0 && fclose(file) == 0);
}

int
main(void)
{
	char path[] = "/tmp/hypertrace-release-keys.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	const std::string private_path = std::string(path) + "/private.pem";
	const std::string peer_path = std::string(path) + "/peer.pem";
	const std::string source_public_path = std::string(path) + "/source.pem";
	const std::string link_path = std::string(path) + "/link.pem";
	const std::string other_path = std::string(path) + "/other.pem";
	EVP_PKEY *source = new_key(EVP_PKEY_ED25519);
	EVP_PKEY *peer = new_key(EVP_PKEY_ED25519);
	EVP_PKEY *other = new_key(EVP_PKEY_ED448);
	write_key(private_path, source, true);
	write_key(source_public_path, source, false);
	write_key(peer_path, peer, false);
	write_key(other_path, other, false);
	assert(symlink(private_path.c_str(), link_path.c_str()) == 0);
	dtraced::release_keys keys;
	assert(!keys.load(link_path.c_str(), peer_path.c_str()) &&
	    (errno == ELOOP || errno == EMLINK));
	assert(!keys.load(private_path.c_str(), other_path.c_str()) &&
	    errno == EPROTO);
	assert(!keys.load(private_path.c_str(), source_public_path.c_str()) &&
	    errno == EPROTO);
	assert(chmod(private_path.c_str(), 0644) == 0);
	assert(!keys.load(private_path.c_str(), peer_path.c_str()) &&
	    errno == EPERM);
	assert(chmod(private_path.c_str(), 0600) == 0);
	assert(keys.load(private_path.c_str(), peer_path.c_str()));
	assert(keys.configured() && keys.private_key() != nullptr);
	assert(keys.own_public() != keys.peer_public());
	assert(!keys.load(private_path.c_str(), peer_path.c_str()) &&
	    errno == EINVAL);
	assert(unlink(link_path.c_str()) == 0);
	assert(unlink(other_path.c_str()) == 0);
	assert(unlink(peer_path.c_str()) == 0);
	assert(unlink(source_public_path.c_str()) == 0);
	assert(unlink(private_path.c_str()) == 0);
	assert(rmdir(path) == 0);
	EVP_PKEY_free(other);
	EVP_PKEY_free(peer);
	EVP_PKEY_free(source);
	return (0);
}
