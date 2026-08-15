/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * CRYPTO descriptor regression tests.
 */

#include <sys/param.h>
#include <sys/cryptodesc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/* Be sure to include the source-tree copy rather than the host copy. */
#include "cryptodev.h"

#include "freebsd_test_suite/macros.h"

static const uint8_t aes_key[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t chacha_key[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const uint8_t hkdf_ikm[22] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};
static const uint8_t hkdf_salt[13] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
};
static const uint8_t hkdf_info[10] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
};
static const uint8_t hkdf_hmac[32] = {
	0x7c, 0xd7, 0xda, 0x31, 0x0a, 0xb0, 0x0b, 0x02,
	0xf4, 0x92, 0x0b, 0x71, 0x4e, 0xe4, 0xde, 0x15,
	0xf4, 0x12, 0xac, 0x47, 0xe2, 0xae, 0x8a, 0x02,
	0x26, 0x21, 0xc3, 0xc2, 0x61, 0xcf, 0xb7, 0xc6,
};
static const uint8_t aes_iv[16] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};
static const uint8_t gcm_iv[12] = {
	0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
	0xde, 0xca, 0xf8, 0x88,
};
static const uint8_t aad[] = "CRYPTO descriptor authenticated data";
static const uint8_t cbc_plaintext[32] = {
	'A', ' ', 'c', 'a', 'p', 'a', 'b', 'i', 'l', 'i', 't', 'y',
	' ', 'c', 'a', 'r', 'r', 'i', 'e', 's', ' ', 'a', 'u', 't',
	'h', 'o', 'r', 'i', 't', 'y', '.', '\n',
};
static const uint8_t aead_plaintext[] =
    "A capability is authority, not a name.";

static int
open_control(void)
{
	int fd;

	fd = open("/dev/crypto", O_RDWR);
	ATF_REQUIRE_MSG(fd >= 0, "open(/dev/crypto): %s", strerror(errno));
	return (fd);
}

static int
mint_descriptor_key(int control, uint32_t cipher, uint32_t mac,
    const uint8_t *key, size_t keylen, int ivlen, int maclen, uint32_t rights)
{
	struct cryptodesc_create create;

	memset(&create, 0, sizeof(create));
	create.session.cipher = cipher;
	create.session.mac = mac;
	create.session.keylen = keylen;
	create.session.key = key;
	create.session.mackeylen = keylen;
	create.session.mackey = key;
	create.session.crid = CRYPTO_FLAG_SOFTWARE;
	create.session.ivlen = ivlen;
	create.session.maclen = maclen;
	create.cd_rights = rights;
	create.cd_fd = -1;
	ATF_REQUIRE_MSG(ioctl(control, CIOCGCRYPTODESC, &create) == 0,
	    "CIOCGCRYPTODESC: %s", strerror(errno));
	ATF_REQUIRE(create.cd_fd >= 0);
	return (create.cd_fd);
}

static int
mint_descriptor(int control, uint32_t cipher, uint32_t mac, int ivlen,
    int maclen, uint32_t rights)
{

	return (mint_descriptor_key(control, cipher, mac, aes_key,
	    sizeof(aes_key), ivlen, maclen, rights));
}

static int
mint_generated_descriptor(int control, uint32_t cipher, uint32_t mac,
    uint32_t keylen, uint32_t mackeylen, int ivlen, int maclen,
    uint32_t rights, uint32_t ttl)
{
	struct cryptodesc_generate create;

	memset(&create, 0, sizeof(create));
	create.session.cipher = cipher;
	create.session.mac = mac;
	create.session.keylen = keylen;
	create.session.mackeylen = mackeylen;
	create.session.crid = CRYPTO_FLAG_SOFTWARE;
	create.session.ivlen = ivlen;
	create.session.maclen = maclen;
	create.cd_rights = rights;
	create.cd_ttl = ttl;
	create.cd_fd = -1;
	ATF_REQUIRE_MSG(ioctl(control, CIOCGCRYPTODESCGENERATE, &create) == 0,
	    "CIOCGCRYPTODESCGENERATE: %s", strerror(errno));
	ATF_REQUIRE(create.cd_fd >= 0);
	return (create.cd_fd);
}

static void
crypt_cbc(int fd, int op, const void *src, void *dst)
{
	struct crypt_op cop;

	memset(&cop, 0, sizeof(cop));
	cop.op = op;
	cop.len = sizeof(cbc_plaintext);
	cop.src = src;
	cop.dst = dst;
	cop.iv = aes_iv;
	ATF_REQUIRE_MSG(ioctl(fd, CIOCCRYPT, &cop) == 0,
	    "CIOCCRYPT: %s", strerror(errno));
}

static int
send_fd(int socket, int fd)
{
	char byte;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	unsigned char control[CMSG_SPACE(sizeof(fd))];

	byte = 'c';
	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	return (sendmsg(socket, &msg, 0));
}

static int
receive_fd(int socket)
{
	char byte;
	int fd;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr msg;
	unsigned char control[CMSG_SPACE(sizeof(fd))];

	fd = -1;
	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	ATF_REQUIRE_MSG(recvmsg(socket, &msg, 0) == 1,
	    "recvmsg: %s", strerror(errno));
	cmsg = CMSG_FIRSTHDR(&msg);
	ATF_REQUIRE(cmsg != NULL);
	ATF_REQUIRE_EQ(cmsg->cmsg_level, SOL_SOCKET);
	ATF_REQUIRE_EQ(cmsg->cmsg_type, SCM_RIGHTS);
	ATF_REQUIRE_EQ(cmsg->cmsg_len, CMSG_LEN(sizeof(fd)));
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	ATF_REQUIRE(fd >= 0);
	return (fd);
}

ATF_TC(mint_validation);
ATF_TC_HEAD(mint_validation, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(mint_validation, tc)
{
	struct cryptodesc_create create;
	int control;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	memset(&create, 0, sizeof(create));
	create.session.cipher = CRYPTO_AES_CBC;
	create.session.key = aes_key;
	create.session.keylen = sizeof(aes_key);
	create.session.crid = CRYPTO_FLAG_SOFTWARE;
	create.cd_fd = 23;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, ioctl(control, CIOCGCRYPTODESC, &create) == -1);
	ATF_REQUIRE_EQ(create.cd_fd, 23);

	create.cd_rights = CRYPTODESC_RIGHT_ENCRYPT | 0x80000000U;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, ioctl(control, CIOCGCRYPTODESC, &create) == -1);

	create.cd_rights = CRYPTODESC_RIGHT_ENCRYPT;
	create.session.ses = 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, ioctl(control, CIOCGCRYPTODESC, &create) == -1);
	close(control);
}

ATF_TC(cbc_rights_and_metadata);
ATF_TC_HEAD(cbc_rights_and_metadata, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(cbc_rights_and_metadata, tc)
{
	uint8_t ciphertext[sizeof(cbc_plaintext)], output[sizeof(cbc_plaintext)];
	struct crypt_op cop;
	struct cryptodesc_restrict attenuation;
	struct cryptodesc_revoke revoke;
	struct session2_op sop;
	struct stat st;
	int control, decrypt_only, encrypt_only, full;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	full = mint_descriptor(control, CRYPTO_AES_CBC, 0, sizeof(aes_iv), 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT);
	ATF_REQUIRE(fstat(full, &st) == 0);
	ATF_REQUIRE(S_ISFIFO(st.st_mode));
	crypt_cbc(full, COP_ENCRYPT, cbc_plaintext, ciphertext);
	crypt_cbc(full, COP_DECRYPT, ciphertext, output);
	ATF_REQUIRE_EQ(memcmp(output, cbc_plaintext, sizeof(output)), 0);

	memset(&cop, 0, sizeof(cop));
	cop.ses = 1;
	cop.op = COP_ENCRYPT;
	cop.len = sizeof(cbc_plaintext);
	cop.src = cbc_plaintext;
	cop.dst = ciphertext;
	cop.iv = aes_iv;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, ioctl(full, CIOCCRYPT, &cop) == -1);
	memset(&sop, 0, sizeof(sop));
	errno = 0;
	ATF_REQUIRE_ERRNO(ENOTTY, ioctl(full, CIOCGSESSION2, &sop) == -1);

	encrypt_only = mint_descriptor(control, CRYPTO_AES_CBC, 0,
	    sizeof(aes_iv), 0, CRYPTODESC_RIGHT_ENCRYPT);
	crypt_cbc(encrypt_only, COP_ENCRYPT, cbc_plaintext, ciphertext);
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_DECRYPT;
	cop.len = sizeof(ciphertext);
	cop.src = ciphertext;
	cop.dst = output;
	cop.iv = aes_iv;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, ioctl(encrypt_only, CIOCCRYPT, &cop) == -1);

	decrypt_only = mint_descriptor(control, CRYPTO_AES_CBC, 0,
	    sizeof(aes_iv), 0, CRYPTODESC_RIGHT_DECRYPT);
	cop.op = COP_ENCRYPT;
	cop.src = cbc_plaintext;
	cop.dst = ciphertext;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, ioctl(decrypt_only, CIOCCRYPT, &cop) == -1);

	memset(&attenuation, 0, sizeof(attenuation));
	attenuation.cd_rights = CRYPTODESC_RIGHT_ENCRYPT;
	ATF_REQUIRE_MSG(ioctl(full, CIOCSCRYPTODESCRIGHTS, &attenuation) == 0,
	    "CIOCSCRYPTODESCRIGHTS: %s", strerror(errno));
	crypt_cbc(full, COP_ENCRYPT, cbc_plaintext, ciphertext);
	cop.op = COP_DECRYPT;
	cop.src = ciphertext;
	cop.dst = output;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, ioctl(full, CIOCCRYPT, &cop) == -1);
	attenuation.cd_rights = CRYPTODESC_RIGHT_ALL;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM,
	    ioctl(full, CIOCSCRYPTODESCRIGHTS, &attenuation) == -1);
	memset(&revoke, 0, sizeof(revoke));
	ATF_REQUIRE_MSG(ioctl(full, CIOCCRYPTODESCREVOKE, &revoke) == 0,
	    "CIOCCRYPTODESCREVOKE: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_ERRNO(EACCES,
	    ioctl(full, CIOCCRYPT, &cop) == -1);
	close(decrypt_only);
	close(encrypt_only);
	close(full);
	close(control);
}

ATF_TC(descriptor_lifecycle);
ATF_TC_HEAD(descriptor_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(descriptor_lifecycle, tc)
{
	uint8_t ciphertext[sizeof(cbc_plaintext)];
	struct crypt_op cop;
	struct cryptodesc_restrict attenuation;
	struct cryptodesc_revoke revoke;
	int control, fd;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	fd = mint_descriptor(control, CRYPTO_AES_CBC, 0, sizeof(aes_iv), 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT);

	attenuation.cd_rights = CRYPTODESC_RIGHT_ENCRYPT | 0x80000000U;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    ioctl(fd, CIOCSCRYPTODESCRIGHTS, &attenuation) == -1);

	attenuation.cd_rights = 0;
	ATF_REQUIRE_MSG(ioctl(fd, CIOCSCRYPTODESCRIGHTS, &attenuation) == 0,
	    "zero-right attenuation: %s", strerror(errno));
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_ENCRYPT;
	cop.len = sizeof(cbc_plaintext);
	cop.src = cbc_plaintext;
	cop.dst = ciphertext;
	cop.iv = aes_iv;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, ioctl(fd, CIOCCRYPT, &cop) == -1);

	revoke.cd_flags = 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    ioctl(fd, CIOCCRYPTODESCREVOKE, &revoke) == -1);
	revoke.cd_flags = 0;
	ATF_REQUIRE_MSG(ioctl(fd, CIOCCRYPTODESCREVOKE, &revoke) == 0,
	    "revoke descriptor: %s", strerror(errno));
	ATF_REQUIRE_MSG(ioctl(fd, CIOCCRYPTODESCREVOKE, &revoke) == 0,
	    "idempotent revocation: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_ERRNO(EACCES,
	    ioctl(fd, CIOCSCRYPTODESCRIGHTS, &attenuation) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EACCES, ioctl(fd, CIOCCRYPT, &cop) == -1);
	close(fd);
	close(control);
}

ATF_TC(digest_and_eta_rights);
ATF_TC_HEAD(digest_and_eta_rights, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(digest_and_eta_rights, tc)
{
	uint8_t ciphertext[sizeof(cbc_plaintext)], output[sizeof(cbc_plaintext)];
	uint8_t digest[32], mac[32];
	struct crypt_op cop;
	int auth, control, eta, eta_encrypt_only, verify;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	auth = mint_descriptor(control, 0, CRYPTO_SHA2_256_HMAC, 0, 0,
	    CRYPTODESC_RIGHT_AUTH);
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_ENCRYPT;
	cop.len = sizeof(aead_plaintext) - 1;
	cop.src = aead_plaintext;
	cop.mac = digest;
	ATF_REQUIRE_MSG(ioctl(auth, CIOCCRYPT, &cop) == 0,
	    "digest authentication: %s", strerror(errno));
	cop.op = COP_DECRYPT;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, ioctl(auth, CIOCCRYPT, &cop) == -1);
	verify = mint_descriptor(control, 0, CRYPTO_SHA2_256_HMAC, 0, 0,
	    CRYPTODESC_RIGHT_VERIFY);
	ATF_REQUIRE_MSG(ioctl(verify, CIOCCRYPT, &cop) == 0,
	    "digest verification right: %s", strerror(errno));

	eta = mint_descriptor(control, CRYPTO_AES_CBC, CRYPTO_SHA2_256_HMAC,
	    sizeof(aes_iv), 0, CRYPTODESC_RIGHT_ALL);
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_ENCRYPT;
	cop.len = sizeof(cbc_plaintext);
	cop.src = cbc_plaintext;
	cop.dst = ciphertext;
	cop.mac = mac;
	cop.iv = aes_iv;
	ATF_REQUIRE_MSG(ioctl(eta, CIOCCRYPT, &cop) == 0,
	    "EtA encrypt: %s", strerror(errno));
	cop.op = COP_DECRYPT;
	cop.src = ciphertext;
	cop.dst = output;
	ATF_REQUIRE_MSG(ioctl(eta, CIOCCRYPT, &cop) == 0,
	    "EtA decrypt: %s", strerror(errno));
	ATF_REQUIRE_EQ(memcmp(output, cbc_plaintext, sizeof(output)), 0);
	mac[0] ^= 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EBADMSG, ioctl(eta, CIOCCRYPT, &cop) == -1);

	eta_encrypt_only = mint_descriptor(control, CRYPTO_AES_CBC,
	    CRYPTO_SHA2_256_HMAC, sizeof(aes_iv), 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_AUTH);
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM,
	    ioctl(eta_encrypt_only, CIOCCRYPT, &cop) == -1);
	close(eta_encrypt_only);
	close(eta);
	close(verify);
	close(auth);
	close(control);
}

ATF_TC(kernel_generated_and_expiry);
ATF_TC_HEAD(kernel_generated_and_expiry, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(kernel_generated_and_expiry, tc)
{
	uint8_t ciphertext[sizeof(cbc_plaintext)];
	struct crypt_op cop;
	int control, fd;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	fd = mint_generated_descriptor(control, CRYPTO_AES_CBC, 0, 16, 0,
	    sizeof(aes_iv), 0, CRYPTODESC_RIGHT_ENCRYPT, 1);
	crypt_cbc(fd, COP_ENCRYPT, cbc_plaintext, ciphertext);
	sleep(2);
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_ENCRYPT;
	cop.len = sizeof(cbc_plaintext);
	cop.src = cbc_plaintext;
	cop.dst = ciphertext;
	cop.iv = aes_iv;
	errno = 0;
	ATF_REQUIRE_ERRNO(ESTALE, ioctl(fd, CIOCCRYPT, &cop) == -1);
	close(fd);
	close(control);
}

ATF_TC(hkdf_opaque_derivation);
ATF_TC_HEAD(hkdf_opaque_derivation, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(hkdf_opaque_derivation, tc)
{
	static const uint8_t message[] = "test message";
	uint8_t output[32];
	struct cryptodesc_create create;
	struct cryptodesc_derive derive;
	struct crypt_op cop;
	int child, control, parent;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	memset(&create, 0, sizeof(create));
	create.session.mac = CRYPTO_SHA2_256_HMAC;
	create.session.mackey = hkdf_ikm;
	create.session.mackeylen = sizeof(hkdf_ikm);
	create.session.crid = CRYPTO_FLAG_SOFTWARE;
	create.cd_rights = CRYPTODESC_RIGHT_DERIVE;
	ATF_REQUIRE_MSG(ioctl(control, CIOCGCRYPTODESC, &create) == 0,
	    "mint HKDF parent: %s", strerror(errno));
	parent = create.cd_fd;
	memset(&derive, 0, sizeof(derive));
	derive.session.mac = CRYPTO_SHA2_256_HMAC;
	derive.session.mackeylen = sizeof(output);
	derive.session.crid = CRYPTO_FLAG_SOFTWARE;
	derive.cd_salt = hkdf_salt;
	derive.cd_salt_len = sizeof(hkdf_salt);
	derive.cd_info = hkdf_info;
	derive.cd_info_len = sizeof(hkdf_info);
	derive.cd_hash = CRYPTODESC_HKDF_SHA256;
	derive.cd_rights = CRYPTODESC_RIGHT_AUTH;
	ATF_REQUIRE_MSG(ioctl(parent, CIOCCRYPTODESCDERIVE, &derive) == 0,
	    "RFC 5869 derivation: %s", strerror(errno));
	child = derive.cd_fd;
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_ENCRYPT;
	cop.len = sizeof(message) - 1;
	cop.src = message;
	cop.mac = output;
	ATF_REQUIRE_MSG(ioctl(child, CIOCCRYPT, &cop) == 0,
	    "derived HMAC: %s", strerror(errno));
	ATF_REQUIRE_MSG(memcmp(output, hkdf_hmac, sizeof(output)) == 0,
	    "derived HMAC starts %02x%02x%02x%02x (expected %02x%02x%02x%02x)",
	    output[0], output[1], output[2], output[3], hkdf_hmac[0],
	    hkdf_hmac[1], hkdf_hmac[2], hkdf_hmac[3]);
	close(child);
	close(parent);
	close(control);
}

ATF_TC(asymmetric_capabilities);
ATF_TC_HEAD(asymmetric_capabilities, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(asymmetric_capabilities, tc)
{
	static const uint8_t message[] = "opaque asymmetric descriptor";
	uint8_t alice_shared[CRYPTODESC_X25519_SIZE];
	uint8_t bob_shared[CRYPTODESC_X25519_SIZE];
	uint8_t signature[CRYPTODESC_ED25519_SIGNATURE_SIZE];
	struct cryptodesc_key_create alice, bob, signer;
	struct cryptodesc_restrict attenuation;
	struct cryptodesc_sign sign;
	struct cryptodesc_verify verify;
	struct cryptodesc_x25519 exchange;
	int control;

	control = open_control();
	memset(&alice, 0, sizeof(alice));
	alice.cd_type = CRYPTODESC_KEY_X25519;
	alice.cd_rights = CRYPTODESC_RIGHT_EXCHANGE;
	ATF_REQUIRE_MSG(ioctl(control, CIOCGCRYPTOKEYDESC, &alice) == 0,
	    "mint Alice X25519 descriptor: %s", strerror(errno));
	memset(&bob, 0, sizeof(bob));
	bob.cd_type = CRYPTODESC_KEY_X25519;
	bob.cd_rights = CRYPTODESC_RIGHT_EXCHANGE;
	ATF_REQUIRE_MSG(ioctl(control, CIOCGCRYPTOKEYDESC, &bob) == 0,
	    "mint Bob X25519 descriptor: %s", strerror(errno));
	memset(&exchange, 0, sizeof(exchange));
	exchange.cd_peer_public = bob.cd_public;
	exchange.cd_peer_public_len = sizeof(bob.cd_public);
	exchange.cd_shared_secret = alice_shared;
	exchange.cd_shared_secret_len = sizeof(alice_shared);
	ATF_REQUIRE_MSG(ioctl(alice.cd_fd, CIOCCRYPTX25519, &exchange) == 0,
	    "Alice exchange: %s", strerror(errno));
	exchange.cd_peer_public = alice.cd_public;
	exchange.cd_shared_secret = bob_shared;
	ATF_REQUIRE_MSG(ioctl(bob.cd_fd, CIOCCRYPTX25519, &exchange) == 0,
	    "Bob exchange: %s", strerror(errno));
	ATF_REQUIRE_EQ(memcmp(alice_shared, bob_shared, sizeof(alice_shared)), 0);
	attenuation.cd_rights = 0;
	ATF_REQUIRE(ioctl(alice.cd_fd, CIOCSCRYPTODESCRIGHTS, &attenuation) == 0);
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, ioctl(alice.cd_fd, CIOCCRYPTX25519,
	    &exchange) == -1);

	memset(&signer, 0, sizeof(signer));
	signer.cd_type = CRYPTODESC_KEY_ED25519;
	signer.cd_rights = CRYPTODESC_RIGHT_SIGN | CRYPTODESC_RIGHT_VERIFY;
	ATF_REQUIRE_MSG(ioctl(control, CIOCGCRYPTOKEYDESC, &signer) == 0,
	    "mint Ed25519 descriptor: %s", strerror(errno));
	memset(&sign, 0, sizeof(sign));
	sign.cd_data = message;
	sign.cd_data_len = sizeof(message) - 1;
	sign.cd_signature = signature;
	sign.cd_signature_len = sizeof(signature);
	ATF_REQUIRE_MSG(ioctl(signer.cd_fd, CIOCCRYPTOSIGN, &sign) == 0,
	    "Ed25519 sign: %s", strerror(errno));
	memset(&verify, 0, sizeof(verify));
	verify.cd_data = message;
	verify.cd_data_len = sizeof(message) - 1;
	verify.cd_signature = signature;
	verify.cd_signature_len = sizeof(signature);
	ATF_REQUIRE_MSG(ioctl(signer.cd_fd, CIOCCRYPTOVERIFY, &verify) == 0,
	    "Ed25519 verify: %s", strerror(errno));
	signature[0] ^= 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EBADMSG, ioctl(signer.cd_fd, CIOCCRYPTOVERIFY,
	    &verify) == -1);
	signature[0] ^= 1;
	attenuation.cd_rights = CRYPTODESC_RIGHT_VERIFY;
	ATF_REQUIRE(ioctl(signer.cd_fd, CIOCSCRYPTODESCRIGHTS, &attenuation) == 0);
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, ioctl(signer.cd_fd, CIOCCRYPTOSIGN, &sign) == -1);
	ATF_REQUIRE(ioctl(signer.cd_fd, CIOCCRYPTOVERIFY, &verify) == 0);
	close(signer.cd_fd);
	close(bob.cd_fd);
	close(alice.cd_fd);
	close(control);
}

ATF_TC(concurrent_descriptor_use);
ATF_TC_HEAD(concurrent_descriptor_use, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(concurrent_descriptor_use, tc)
{
	uint8_t ciphertext[sizeof(cbc_plaintext)], output[sizeof(cbc_plaintext)];
	struct crypt_op cop;
	int child, control, fd, i, status;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	fd = mint_generated_descriptor(control, CRYPTO_AES_CBC, 0, 16, 0,
	    sizeof(aes_iv), 0, CRYPTODESC_RIGHT_ENCRYPT |
	    CRYPTODESC_RIGHT_DECRYPT, 0);
	for (child = 0; child < 8; child++) {
		ATF_REQUIRE((i = fork()) >= 0);
		if (i == 0) {
			for (i = 0; i < 64; i++) {
				memset(&cop, 0, sizeof(cop));
				cop.op = COP_ENCRYPT;
				cop.len = sizeof(cbc_plaintext);
				cop.src = cbc_plaintext;
				cop.dst = ciphertext;
				cop.iv = aes_iv;
				if (ioctl(fd, CIOCCRYPT, &cop) != 0)
					_exit(1);
				cop.op = COP_DECRYPT;
				cop.src = ciphertext;
				cop.dst = output;
				if (ioctl(fd, CIOCCRYPT, &cop) != 0 ||
				    memcmp(output, cbc_plaintext, sizeof(output)) != 0)
					_exit(1);
			}
			_exit(0);
		}
	}
	for (child = 0; child < 8; child++) {
		ATF_REQUIRE(wait(&status) >= 0);
		ATF_REQUIRE(WIFEXITED(status));
		ATF_REQUIRE_EQ(WEXITSTATUS(status), 0);
	}
	close(fd);
	close(control);
}

ATF_TC(passable_descriptor);
ATF_TC_HEAD(passable_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(passable_descriptor, tc)
{
	uint8_t ciphertext[sizeof(cbc_plaintext)], output[sizeof(cbc_plaintext)];
	struct crypt_op cop;
	struct cryptodesc_restrict attenuation;
	int control, fd, sockets[2], transferred;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	fd = mint_descriptor(control, CRYPTO_AES_CBC, 0, sizeof(aes_iv), 0,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	ATF_REQUIRE_MSG(send_fd(sockets[0], fd) == 1, "sendmsg: %s",
	    strerror(errno));
	transferred = receive_fd(sockets[1]);
	close(fd);
	crypt_cbc(transferred, COP_ENCRYPT, cbc_plaintext, ciphertext);
	crypt_cbc(transferred, COP_DECRYPT, ciphertext, output);
	ATF_REQUIRE_EQ(memcmp(output, cbc_plaintext, sizeof(output)), 0);

	attenuation.cd_rights = CRYPTODESC_RIGHT_ENCRYPT;
	ATF_REQUIRE_MSG(ioctl(transferred, CIOCSCRYPTODESCRIGHTS,
	    &attenuation) == 0, "attenuate transferred descriptor: %s",
	    strerror(errno));
	crypt_cbc(transferred, COP_ENCRYPT, cbc_plaintext, ciphertext);
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_DECRYPT;
	cop.len = sizeof(ciphertext);
	cop.src = ciphertext;
	cop.dst = output;
	cop.iv = aes_iv;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM,
	    ioctl(transferred, CIOCCRYPT, &cop) == -1);
	close(transferred);
	close(sockets[0]);
	close(sockets[1]);
	close(control);
}

ATF_TC(aead_rights_and_integrity);
ATF_TC_HEAD(aead_rights_and_integrity, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(aead_rights_and_integrity, tc)
{
	uint8_t ciphertext[sizeof(aead_plaintext) - 1];
	uint8_t output[sizeof(aead_plaintext) - 1];
	uint8_t tag[16];
	struct crypt_aead caead;
	int chacha, control, encrypt_only, full;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	full = mint_descriptor(control, CRYPTO_AES_NIST_GCM_16, 0,
	    sizeof(gcm_iv), sizeof(tag), CRYPTODESC_RIGHT_ALL);
	memset(&caead, 0, sizeof(caead));
	caead.op = COP_ENCRYPT;
	caead.len = sizeof(aead_plaintext) - 1;
	caead.aadlen = sizeof(aad) - 1;
	caead.ivlen = sizeof(gcm_iv);
	caead.src = aead_plaintext;
	caead.dst = ciphertext;
	caead.aad = aad;
	caead.tag = tag;
	caead.iv = gcm_iv;
	ATF_REQUIRE_MSG(ioctl(full, CIOCCRYPTAEAD, &caead) == 0,
	    "CIOCCRYPTAEAD encrypt: %s", strerror(errno));
	caead.op = COP_DECRYPT;
	caead.src = ciphertext;
	caead.dst = output;
	ATF_REQUIRE_MSG(ioctl(full, CIOCCRYPTAEAD, &caead) == 0,
	    "CIOCCRYPTAEAD decrypt: %s", strerror(errno));
	ATF_REQUIRE_EQ(memcmp(output, aead_plaintext, sizeof(output)), 0);
	tag[0] ^= 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EBADMSG, ioctl(full, CIOCCRYPTAEAD, &caead) == -1);

	encrypt_only = mint_descriptor(control, CRYPTO_AES_NIST_GCM_16, 0,
	    sizeof(gcm_iv), sizeof(tag),
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_AUTH);
	memset(&caead, 0, sizeof(caead));
	caead.op = COP_DECRYPT;
	caead.len = sizeof(aead_plaintext) - 1;
	caead.aadlen = sizeof(aad) - 1;
	caead.ivlen = sizeof(gcm_iv);
	caead.src = ciphertext;
	caead.dst = output;
	caead.aad = aad;
	caead.tag = tag;
	caead.iv = gcm_iv;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM,
	    ioctl(encrypt_only, CIOCCRYPTAEAD, &caead) == -1);

	chacha = mint_descriptor_key(control, CRYPTO_CHACHA20_POLY1305, 0,
	    chacha_key, sizeof(chacha_key), sizeof(gcm_iv), sizeof(tag),
	    CRYPTODESC_RIGHT_ALL);
	memset(&caead, 0, sizeof(caead));
	caead.op = COP_ENCRYPT;
	caead.len = sizeof(aead_plaintext) - 1;
	caead.aadlen = sizeof(aad) - 1;
	caead.ivlen = sizeof(gcm_iv);
	caead.src = aead_plaintext;
	caead.dst = ciphertext;
	caead.aad = aad;
	caead.tag = tag;
	caead.iv = gcm_iv;
	ATF_REQUIRE_MSG(ioctl(chacha, CIOCCRYPTAEAD, &caead) == 0,
	    "ChaCha20-Poly1305 encrypt: %s", strerror(errno));
	caead.op = COP_DECRYPT;
	caead.src = ciphertext;
	caead.dst = output;
	ATF_REQUIRE_MSG(ioctl(chacha, CIOCCRYPTAEAD, &caead) == 0,
	    "ChaCha20-Poly1305 decrypt: %s", strerror(errno));
	ATF_REQUIRE_EQ(memcmp(output, aead_plaintext, sizeof(output)), 0);
	close(chacha);
	close(encrypt_only);
	close(full);
	close(control);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mint_validation);
	ATF_TP_ADD_TC(tp, cbc_rights_and_metadata);
	ATF_TP_ADD_TC(tp, descriptor_lifecycle);
	ATF_TP_ADD_TC(tp, digest_and_eta_rights);
	ATF_TP_ADD_TC(tp, kernel_generated_and_expiry);
	ATF_TP_ADD_TC(tp, hkdf_opaque_derivation);
	ATF_TP_ADD_TC(tp, asymmetric_capabilities);
	ATF_TP_ADD_TC(tp, concurrent_descriptor_use);
	ATF_TP_ADD_TC(tp, passable_descriptor);
	ATF_TP_ADD_TC(tp, aead_rights_and_integrity);
	return (atf_no_error());
}
