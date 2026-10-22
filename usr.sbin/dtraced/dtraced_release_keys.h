/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_RELEASE_KEYS_H
#define DTRACED_RELEASE_KEYS_H

#include <sys/stat.h>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <unistd.h>

namespace dtraced {

/* A configured pair is a local credential and an independently pinned peer.
 * Neither key may come from the checkpoint or from a remote wire frame. */
class release_keys {
	EVP_PKEY *private_key_ = nullptr;
	std::array<uint8_t, 32> own_public_{};
	std::array<uint8_t, 32> peer_public_{};
	static int no_password(char *, int, int, void *) { return (0); }

	static EVP_PKEY *read_pem(const char *path, bool private_key)
	{
		if (path == nullptr || path[0] != '/') {
			errno = EINVAL;
			return (nullptr);
		}
		int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0)
			return (nullptr);
		struct stat sb;
		int error = fstat(fd, &sb) != 0 ? errno : 0;
		if (error == 0 && (!S_ISREG(sb.st_mode) || sb.st_nlink != 1 ||
		    sb.st_uid != geteuid() || sb.st_size == 0 ||
		    sb.st_size > 16384 || (sb.st_mode & (private_key ? 077 : 022)) != 0))
			error = EPERM;
		BIO *bio = error == 0 ? BIO_new_fd(fd, BIO_NOCLOSE) : nullptr;
		if (error == 0 && bio == nullptr)
			error = ENOMEM;
		EVP_PKEY *key = nullptr;
		if (error == 0) {
			key = private_key ? PEM_read_bio_PrivateKey(bio, nullptr,
			    no_password, nullptr) : PEM_read_bio_PUBKEY(bio, nullptr,
			    nullptr, nullptr);
			if (key == nullptr)
				error = EPROTO;
		}
		BIO_free(bio);
		if (close(fd) != 0 && error == 0)
			error = errno;
		if (error != 0) {
			EVP_PKEY_free(key);
			errno = error;
			return (nullptr);
		}
		return (key);
	}

public:
	release_keys() = default;
	release_keys(const release_keys &) = delete;
	release_keys &operator=(const release_keys &) = delete;
	~release_keys() { EVP_PKEY_free(private_key_); }

	bool load(const char *private_path, const char *peer_path)
	{
		if (private_key_ != nullptr || private_path == nullptr ||
		    peer_path == nullptr) {
			errno = EINVAL;
			return (false);
		}
		EVP_PKEY *local = read_pem(private_path, true);
		if (local == nullptr)
			return (false);
		EVP_PKEY *peer = read_pem(peer_path, false);
		if (peer == nullptr) {
			int error = errno;
			EVP_PKEY_free(local);
			errno = error;
			return (false);
		}
		std::array<uint8_t, 32> own{}, remote{};
		size_t own_length = own.size(), peer_length = remote.size();
		bool valid = EVP_PKEY_base_id(local) == EVP_PKEY_ED25519 &&
		    EVP_PKEY_base_id(peer) == EVP_PKEY_ED25519 &&
		    EVP_PKEY_get_raw_public_key(local, own.data(), &own_length) == 1 &&
		    EVP_PKEY_get_raw_public_key(peer, remote.data(), &peer_length) == 1 &&
		    own_length == own.size() && peer_length == remote.size() &&
		    own != remote;
		EVP_PKEY_free(peer);
		if (!valid) {
			EVP_PKEY_free(local);
			errno = EPROTO;
			return (false);
		}
		private_key_ = local;
		own_public_ = own;
		peer_public_ = remote;
		return (true);
	}

	bool configured() const { return (private_key_ != nullptr); }
/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
	EVP_PKEY *private_key() const { return (private_key_); }
	const std::array<uint8_t, 32> &own_public() const { return (own_public_); }
	const std::array<uint8_t, 32> &peer_public() const { return (peer_public_); }
/* HT-C END */
};

} // namespace dtraced
#endif
