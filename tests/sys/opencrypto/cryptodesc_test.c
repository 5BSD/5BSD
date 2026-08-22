/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * CRYPTO descriptor regression tests.
 */

#include <sys/param.h>
#include <sys/cryptodesc.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
named_control(struct cryptodesc_named_control *control, const char *name,
    const char *owner)
{

	memset(control, 0, sizeof(*control));
	strlcpy(control->cd_name, name, sizeof(control->cd_name));
	strlcpy(control->cd_owner, owner, sizeof(control->cd_owner));
}

static void
create_named_cbc(int control, const char *name, const char *owner,
    uint32_t rights)
{
	struct cryptodesc_named_create create;

	memset(&create, 0, sizeof(create));
	strlcpy(create.cd_name, name, sizeof(create.cd_name));
	strlcpy(create.cd_owner, owner, sizeof(create.cd_owner));
	create.cd_session.cipher = CRYPTO_AES_CBC;
	create.cd_session.keylen = 32;
	create.cd_session.crid = CRYPTO_FLAG_SOFTWARE;
	create.cd_session.ivlen = sizeof(aes_iv);
	create.cd_rights = rights;
	ATF_REQUIRE_MSG(ioctl(control, CIOCGCRYPTONAMEDKEY, &create) == 0,
	    "CIOCGCRYPTONAMEDKEY: %s", strerror(errno));
	ATF_REQUIRE_EQ(create.cd_generation, 1);
}

static int
lease_named(int control, const char *name, const char *owner, uint32_t rights)
{
	struct cryptodesc_named_lease lease;

	memset(&lease, 0, sizeof(lease));
	strlcpy(lease.cd_name, name, sizeof(lease.cd_name));
	strlcpy(lease.cd_owner, owner, sizeof(lease.cd_owner));
	lease.cd_rights = rights;
	lease.cd_ttl = 60;
	lease.cd_fd = -1;
	ATF_REQUIRE_MSG(ioctl(control, CIOCGCRYPTONAMEDLEASE, &lease) == 0,
	    "CIOCGCRYPTONAMEDLEASE: %s", strerror(errno));
	ATF_REQUIRE(lease.cd_fd >= 0);
	return (lease.cd_fd);
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

static void
wait_for_event(int kq, struct kevent *event, int seconds, int expected)
{
	struct timespec timeout;
	int count;

	timeout.tv_sec = seconds;
	timeout.tv_nsec = 0;
	count = kevent(kq, NULL, 0, event, 1, &timeout);
	ATF_REQUIRE_MSG(count == expected, "kevent returned %d: %s", count,
	    count == -1 ? strerror(errno) : "unexpected event count");
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

ATF_TC(descriptor_kinfo);
ATF_TC_HEAD(descriptor_kinfo, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CRYPTO descriptors expose their type and safe metadata to process tools");
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(descriptor_kinfo, tc)
{
	struct kinfo_file *files;
	int control, count, descriptor, i;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	descriptor = mint_descriptor(control, CRYPTO_AES_CBC, 0,
	    sizeof(aes_iv), 0, CRYPTODESC_RIGHT_ENCRYPT);
	files = kinfo_getfile(getpid(), &count);
	ATF_REQUIRE_MSG(files != NULL, "kinfo_getfile: %s", strerror(errno));
	for (i = 0; i < count && files[i].kf_fd != descriptor; i++)
		;
	ATF_REQUIRE_MSG(i != count, "descriptor fd %d was not exported",
	    descriptor);
	ATF_REQUIRE_EQ(KF_TYPE_CRYPTO, files[i].kf_type);
	ATF_REQUIRE((files[i].kf_status & KF_ATTR_VALID) != 0);
	ATF_REQUIRE_MSG(strncmp(files[i].kf_path, "crypto:", 7) == 0,
	    "unexpected descriptor name: %s", files[i].kf_path);
	ATF_REQUIRE(strstr(files[i].kf_path, ":rights=") != NULL);
	free(files);
	close(descriptor);
	close(control);
}

ATF_TC(cbc_rights_and_metadata);
ATF_TC_HEAD(cbc_rights_and_metadata, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}

ATF_TC(descriptor_metadata_and_kqueue);
ATF_TC_HEAD(descriptor_metadata_and_kqueue, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CRYPTO descriptors expose structured metadata and lifecycle events");
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(descriptor_metadata_and_kqueue, tc)
{
	struct cryptodesc_info info;
	struct cryptodesc_named_control named;
	struct cryptodesc_restrict attenuation;
	struct cryptodesc_revoke revoke;
	struct kevent change, event;
	struct kinfo_file *files;
	char name[CRYPTODESC_KEY_NAME_MAX];
	const char *owner;
	int control, count, fd, i, kq;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	fd = mint_generated_descriptor(control, CRYPTO_AES_CBC, 0, 16, 0,
	    sizeof(aes_iv), 0, CRYPTODESC_RIGHT_ENCRYPT |
	    CRYPTODESC_RIGHT_DECRYPT, 60);

	memset(&info, 0, sizeof(info));
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    ioctl(fd, CIOCGCRYPTODESCINFO, &info) == -1);
	info.cd_size = sizeof(info);
	ATF_REQUIRE_MSG(ioctl(fd, CIOCGCRYPTODESCINFO, &info) == 0,
	    "CIOCGCRYPTODESCINFO: %s", strerror(errno));
	ATF_REQUIRE_EQ(info.cd_type, 0);
	ATF_REQUIRE_EQ(info.cd_rights, CRYPTODESC_RIGHT_ENCRYPT |
	    CRYPTODESC_RIGHT_DECRYPT);
	ATF_REQUIRE_EQ(info.cd_state, 0);
	ATF_REQUIRE(info.cd_crid >= 0);
	ATF_REQUIRE((info.cd_provider_flags & CRYPTO_FLAG_SOFTWARE) != 0);
	ATF_REQUIRE(info.cd_expires > time(NULL));
	ATF_REQUIRE_EQ(info.cd_generation, 0);
	ATF_REQUIRE_EQ(info.cd_key_generation, 0);

	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&change, fd, EVFILT_CRYPTODESC, EV_ADD, 0, 0, NULL);
	ATF_REQUIRE_ERRNO(EINVAL,
	    kevent(kq, &change, 1, NULL, 0, NULL) == -1);
	EV_SET(&change, fd, EVFILT_CRYPTODESC, EV_ADD, 0x20, 0, NULL);
	ATF_REQUIRE_ERRNO(EINVAL,
	    kevent(kq, &change, 1, NULL, 0, NULL) == -1);
	EV_SET(&change, fd, EVFILT_CRYPTODESC, EV_ADD,
	    NOTE_CRYPTODESC_RIGHTS | NOTE_CRYPTODESC_REVOKE, 0, NULL);
	ATF_REQUIRE_EQ(kevent(kq, &change, 1, NULL, 0, NULL), 0);
	wait_for_event(kq, &event, 0, 0);

	attenuation.cd_rights = CRYPTODESC_RIGHT_ENCRYPT;
	ATF_REQUIRE_EQ(ioctl(fd, CIOCSCRYPTODESCRIGHTS, &attenuation), 0);
	wait_for_event(kq, &event, 1, 1);
	ATF_REQUIRE_EQ(event.filter, EVFILT_CRYPTODESC);
	ATF_REQUIRE_EQ(event.fflags, NOTE_CRYPTODESC_RIGHTS);
	ATF_REQUIRE_EQ(event.data, CRYPTODESC_RIGHT_ENCRYPT);
	ATF_REQUIRE_EQ(event.ext[0], 0);
	ATF_REQUIRE_EQ(event.ext[1], (uint64_t)info.cd_expires);
	wait_for_event(kq, &event, 0, 0);

	memset(&revoke, 0, sizeof(revoke));
	ATF_REQUIRE_EQ(ioctl(fd, CIOCCRYPTODESCREVOKE, &revoke), 0);
	wait_for_event(kq, &event, 1, 1);
	ATF_REQUIRE_EQ(event.fflags, NOTE_CRYPTODESC_REVOKE);
	ATF_REQUIRE((event.flags & EV_EOF) != 0);
	info.cd_size = sizeof(info);
	ATF_REQUIRE_EQ(ioctl(fd, CIOCGCRYPTODESCINFO, &info), 0);
	ATF_REQUIRE((info.cd_state & CRYPTODESC_STATE_REVOKED) != 0);
	close(kq);
	close(fd);

	/* TTL expiry wakes kqueue without requiring a crypto operation. */
	fd = mint_generated_descriptor(control, CRYPTO_AES_CBC, 0, 16, 0,
	    sizeof(aes_iv), 0, CRYPTODESC_RIGHT_ENCRYPT, 1);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&change, fd, EVFILT_CRYPTODESC, EV_ADD,
	    NOTE_CRYPTODESC_EXPIRE, 0, NULL);
	ATF_REQUIRE_EQ(kevent(kq, &change, 1, NULL, 0, NULL), 0);
	wait_for_event(kq, &event, 3, 1);
	ATF_REQUIRE_EQ(event.fflags, NOTE_CRYPTODESC_EXPIRE);
	ATF_REQUIRE((event.flags & EV_EOF) != 0);
	close(kq);
	close(fd);

	/* Rotation reports both the leased and newest named-key generations. */
	snprintf(name, sizeof(name), "kqueue-%ld", (long)getpid());
	owner = "cryptodesc-test";
	create_named_cbc(control, name, owner, CRYPTODESC_RIGHT_ENCRYPT);
	fd = lease_named(control, name, owner, CRYPTODESC_RIGHT_ENCRYPT);
	info.cd_size = sizeof(info);
	ATF_REQUIRE_EQ(ioctl(fd, CIOCGCRYPTODESCINFO, &info), 0);
	ATF_REQUIRE_EQ(info.cd_generation, 1);
	ATF_REQUIRE_EQ(info.cd_key_generation, 1);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&change, fd, EVFILT_CRYPTODESC, EV_ADD,
	    NOTE_CRYPTODESC_KEY_ROTATE | NOTE_CRYPTODESC_KEY_DELETE, 0, NULL);
	ATF_REQUIRE_EQ(kevent(kq, &change, 1, NULL, 0, NULL), 0);
	named_control(&named, name, owner);
	ATF_REQUIRE_EQ(ioctl(control, CIOCCRYPTONAMEDROTATE, &named), 0);
	ATF_REQUIRE_EQ(named.cd_generation, 2);
	wait_for_event(kq, &event, 1, 1);
	ATF_REQUIRE_EQ(event.fflags, NOTE_CRYPTODESC_KEY_ROTATE);
	ATF_REQUIRE_EQ(event.ext[0], 1);
	ATF_REQUIRE_EQ(event.ext[2], 2);
	info.cd_size = sizeof(info);
	ATF_REQUIRE_EQ(ioctl(fd, CIOCGCRYPTODESCINFO, &info), 0);
	ATF_REQUIRE_EQ(info.cd_generation, 1);
	ATF_REQUIRE_EQ(info.cd_key_generation, 2);
	ATF_REQUIRE((info.cd_state & CRYPTODESC_STATE_KEY_INVALID) != 0);
	files = kinfo_getfile(getpid(), &count);
	ATF_REQUIRE(files != NULL);
	for (i = 0; i < count && files[i].kf_fd != fd; i++)
		;
	ATF_REQUIRE(i != count);
	ATF_REQUIRE(strstr(files[i].kf_path, ":expires=") != NULL);
	ATF_REQUIRE(strstr(files[i].kf_path,
	    ":generation=1:key-generation=2:key-invalid=1") != NULL);
	free(files);
	close(kq);
	close(fd);

	fd = lease_named(control, name, owner, CRYPTODESC_RIGHT_ENCRYPT);
	kq = kqueue();
	ATF_REQUIRE(kq >= 0);
	EV_SET(&change, fd, EVFILT_CRYPTODESC, EV_ADD,
	    NOTE_CRYPTODESC_KEY_DELETE, 0, NULL);
	ATF_REQUIRE_EQ(kevent(kq, &change, 1, NULL, 0, NULL), 0);
	named_control(&named, name, owner);
	ATF_REQUIRE_EQ(ioctl(control, CIOCCRYPTONAMEDDELETE, &named), 0);
	ATF_REQUIRE_EQ(named.cd_generation, 3);
	wait_for_event(kq, &event, 1, 1);
	ATF_REQUIRE_EQ(event.fflags, NOTE_CRYPTODESC_KEY_DELETE);
	ATF_REQUIRE_EQ(event.ext[0], 2);
	ATF_REQUIRE_EQ(event.ext[2], 3);
	info.cd_size = sizeof(info);
	ATF_REQUIRE_EQ(ioctl(fd, CIOCGCRYPTODESCINFO, &info), 0);
	ATF_REQUIRE_EQ(info.cd_generation, 2);
	ATF_REQUIRE_EQ(info.cd_key_generation, 3);
	ATF_REQUIRE((info.cd_state & CRYPTODESC_STATE_KEY_INVALID) != 0);
	close(kq);
	close(fd);
	close(control);
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

ATF_TC(named_key_lifecycle);
ATF_TC_HEAD(named_key_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(named_key_lifecycle, tc)
{
	const char *name = "lifecycle-test";
	const char *owner = "service.alpha";
	uint8_t ciphertext[sizeof(cbc_plaintext)], output[sizeof(cbc_plaintext)];
	struct cryptodesc_named_control control_request;
	struct cryptodesc_named_create duplicate;
	struct cryptodesc_named_lease lease;
	int control, decryptor, encryptor, replacement;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	create_named_cbc(control, name, owner,
	    CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT);
	memset(&duplicate, 0, sizeof(duplicate));
	strlcpy(duplicate.cd_name, name, sizeof(duplicate.cd_name));
	strlcpy(duplicate.cd_owner, owner, sizeof(duplicate.cd_owner));
	duplicate.cd_session.cipher = CRYPTO_AES_CBC;
	duplicate.cd_session.keylen = 32;
	duplicate.cd_session.crid = CRYPTO_FLAG_SOFTWARE;
	duplicate.cd_session.ivlen = sizeof(aes_iv);
	duplicate.cd_rights = CRYPTODESC_RIGHT_ENCRYPT;
	errno = 0;
	ATF_REQUIRE_ERRNO(EEXIST,
	    ioctl(control, CIOCGCRYPTONAMEDKEY, &duplicate) == -1);

	memset(&lease, 0, sizeof(lease));
	strlcpy(lease.cd_name, name, sizeof(lease.cd_name));
	strlcpy(lease.cd_owner, "service.beta", sizeof(lease.cd_owner));
	lease.cd_rights = CRYPTODESC_RIGHT_ENCRYPT;
	errno = 0;
	ATF_REQUIRE_ERRNO(ENOENT,
	    ioctl(control, CIOCGCRYPTONAMEDLEASE, &lease) == -1);
	strlcpy(lease.cd_owner, owner, sizeof(lease.cd_owner));
	lease.cd_rights = CRYPTODESC_RIGHT_AUTH;
	errno = 0;
	ATF_REQUIRE_ERRNO(EACCES,
	    ioctl(control, CIOCGCRYPTONAMEDLEASE, &lease) == -1);
	lease.cd_rights = CRYPTODESC_RIGHT_ENCRYPT;
	lease.cd_pad = 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL,
	    ioctl(control, CIOCGCRYPTONAMEDLEASE, &lease) == -1);
	lease.cd_pad = 0;

	encryptor = lease_named(control, name, owner, CRYPTODESC_RIGHT_ENCRYPT);
	decryptor = lease_named(control, name, owner, CRYPTODESC_RIGHT_DECRYPT);
	crypt_cbc(encryptor, COP_ENCRYPT, cbc_plaintext, ciphertext);
	crypt_cbc(decryptor, COP_DECRYPT, ciphertext, output);
	ATF_REQUIRE_EQ(memcmp(output, cbc_plaintext, sizeof(output)), 0);

	named_control(&control_request, name, owner);
	ATF_REQUIRE_MSG(ioctl(control, CIOCCRYPTONAMEDROTATE,
	    &control_request) == 0, "CIOCCRYPTONAMEDROTATE: %s", strerror(errno));
	ATF_REQUIRE_EQ(control_request.cd_generation, 2);
	errno = 0;
	ATF_REQUIRE_ERRNO(EACCES,
	    ioctl(encryptor, CIOCCRYPT, &(struct crypt_op){ .op = COP_ENCRYPT,
	    .len = sizeof(cbc_plaintext), .src = cbc_plaintext, .dst = ciphertext,
	    .iv = aes_iv }) == -1);
	close(encryptor);
	close(decryptor);

	encryptor = lease_named(control, name, owner, CRYPTODESC_RIGHT_ENCRYPT);
	replacement = lease_named(control, name, owner, CRYPTODESC_RIGHT_DECRYPT);
	crypt_cbc(encryptor, COP_ENCRYPT, cbc_plaintext, ciphertext);
	crypt_cbc(replacement, COP_DECRYPT, ciphertext, output);
	ATF_REQUIRE_EQ(memcmp(output, cbc_plaintext, sizeof(output)), 0);
	named_control(&control_request, name, owner);
	ATF_REQUIRE_MSG(ioctl(control, CIOCCRYPTONAMEDDELETE,
	    &control_request) == 0, "CIOCCRYPTONAMEDDELETE: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_ERRNO(EACCES,
	    ioctl(encryptor, CIOCCRYPT, &(struct crypt_op){ .op = COP_ENCRYPT,
	    .len = sizeof(cbc_plaintext), .src = cbc_plaintext, .dst = ciphertext,
	    .iv = aes_iv }) == -1);
	close(encryptor);
	close(replacement);
	errno = 0;
	ATF_REQUIRE_ERRNO(ENOENT,
	    ioctl(control, CIOCGCRYPTONAMEDLEASE, &lease) == -1);
	close(control);
}
ATF_TC_BODY(kernel_generated_and_expiry, tc)
{
	uint8_t ciphertext[sizeof(cbc_plaintext)];
	struct cryptodesc_info parent_info, child_info;
	struct cryptodesc_derive derive;
	struct crypt_op cop;
	int child, control, fd, parent;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	fd = mint_generated_descriptor(control, CRYPTO_AES_CBC, 0, 16, 0,
	    sizeof(aes_iv), 0, CRYPTODESC_RIGHT_ENCRYPT, 1);
	crypt_cbc(fd, COP_ENCRYPT, cbc_plaintext, ciphertext);
	parent = mint_generated_descriptor(control, 0, CRYPTO_SHA2_256_HMAC,
	    0, 32, 0, 0,
	    CRYPTODESC_RIGHT_AUTH | CRYPTODESC_RIGHT_DERIVE, 1);
	memset(&derive, 0, sizeof(derive));
	derive.session.mac = CRYPTO_SHA2_256_HMAC;
	derive.session.mackeylen = 32;
	derive.session.crid = CRYPTO_FLAG_SOFTWARE;
	derive.cd_hash = CRYPTODESC_HKDF_SHA256;
	derive.cd_rights = CRYPTODESC_RIGHT_AUTH;
	derive.cd_ttl = 3600;
	ATF_REQUIRE_EQ(0, ioctl(parent, CIOCCRYPTODESCDERIVE, &derive));
	child = derive.cd_fd;
	memset(&parent_info, 0, sizeof(parent_info));
	parent_info.cd_size = sizeof(parent_info);
	memset(&child_info, 0, sizeof(child_info));
	child_info.cd_size = sizeof(child_info);
	ATF_REQUIRE_EQ(0, ioctl(parent, CIOCGCRYPTODESCINFO, &parent_info));
	ATF_REQUIRE_EQ(0, ioctl(child, CIOCGCRYPTODESCINFO, &child_info));
	ATF_CHECK_EQ(parent_info.cd_expires, child_info.cd_expires);
	sleep(2);
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_ENCRYPT;
	cop.len = sizeof(cbc_plaintext);
	cop.src = cbc_plaintext;
	cop.dst = ciphertext;
	cop.iv = aes_iv;
	errno = 0;
	ATF_REQUIRE_ERRNO(ESTALE, ioctl(fd, CIOCCRYPT, &cop) == -1);
	cop.op = COP_ENCRYPT;
	cop.len = 1;
	cop.src = "x";
	cop.dst = NULL;
	cop.mac = ciphertext;
	errno = 0;
	ATF_REQUIRE_ERRNO(ESTALE, ioctl(child, CIOCCRYPT, &cop) == -1);
	close(child);
	close(parent);
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
	create.cd_rights = CRYPTODESC_RIGHT_AUTH | CRYPTODESC_RIGHT_DERIVE;
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

ATF_TC(derive_authority_and_lineage);
ATF_TC_HEAD(derive_authority_and_lineage, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC(derive_uses_complete_session_secret);
ATF_TC_HEAD(derive_uses_complete_session_secret, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
}
ATF_TC_BODY(derive_uses_complete_session_secret, tc)
{
	static const uint8_t message[] = "complete session secret";
	struct cryptodesc_create create;
	struct cryptodesc_derive derive;
	struct crypt_op cop;
	uint8_t mac_keys[2][32], outputs[2][32];
	int child, control, i, parent;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();
	memset(mac_keys[0], 0x5a, sizeof(mac_keys[0]));
	memcpy(mac_keys[1], mac_keys[0], sizeof(mac_keys[1]));
	mac_keys[1][0] ^= 0x80;
	for (i = 0; i < 2; i++) {
		memset(&create, 0, sizeof(create));
		create.session.cipher = CRYPTO_AES_CBC;
		create.session.mac = CRYPTO_SHA2_256_HMAC;
		create.session.key = aes_key;
		create.session.keylen = sizeof(aes_key);
		create.session.mackey = mac_keys[i];
		create.session.mackeylen = sizeof(mac_keys[i]);
		create.session.crid = CRYPTO_FLAG_SOFTWARE;
		create.session.ivlen = sizeof(aes_iv);
		create.cd_rights = CRYPTODESC_RIGHT_AUTH |
		    CRYPTODESC_RIGHT_DERIVE;
		ATF_REQUIRE_EQ(0, ioctl(control, CIOCGCRYPTODESC, &create));
		parent = create.cd_fd;
		memset(&derive, 0, sizeof(derive));
		derive.session.mac = CRYPTO_SHA2_256_HMAC;
		derive.session.mackeylen = sizeof(outputs[i]);
		derive.session.crid = CRYPTO_FLAG_SOFTWARE;
		derive.cd_hash = CRYPTODESC_HKDF_SHA256;
		derive.cd_rights = CRYPTODESC_RIGHT_AUTH;
		ATF_REQUIRE_EQ(0,
		    ioctl(parent, CIOCCRYPTODESCDERIVE, &derive));
		child = derive.cd_fd;
		memset(&cop, 0, sizeof(cop));
		cop.op = COP_ENCRYPT;
		cop.len = sizeof(message) - 1;
		cop.src = message;
		cop.mac = outputs[i];
		ATF_REQUIRE_EQ(0, ioctl(child, CIOCCRYPT, &cop));
		close(child);
		close(parent);
	}
	ATF_CHECK_MSG(memcmp(outputs[0], outputs[1], sizeof(outputs[0])) != 0,
	    "changing only the MAC key did not change the derived child");
	explicit_bzero(mac_keys, sizeof(mac_keys));
	explicit_bzero(outputs, sizeof(outputs));
	close(control);
}
ATF_TC_BODY(derive_authority_and_lineage, tc)
{
	static const char name[] = "derive-lineage";
	static const char owner[] = "service.derive";
	static const uint8_t message[] = "lineage";
	struct cryptodesc_named_control rotate;
	struct cryptodesc_named_create named;
	struct cryptodesc_derive derive;
	struct cryptodesc_create create;
	struct crypt_op cop;
	uint8_t digest[32];
	int child, control, parent;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	control = open_control();

	/* Derivation cannot manufacture operation rights absent from its parent. */
	memset(&create, 0, sizeof(create));
	create.session.mac = CRYPTO_SHA2_256_HMAC;
	create.session.mackey = hkdf_ikm;
	create.session.mackeylen = sizeof(hkdf_ikm);
	create.session.crid = CRYPTO_FLAG_SOFTWARE;
	create.cd_rights = CRYPTODESC_RIGHT_DERIVE;
	ATF_REQUIRE_EQ(0, ioctl(control, CIOCGCRYPTODESC, &create));
	parent = create.cd_fd;
	memset(&derive, 0, sizeof(derive));
	derive.session.mac = CRYPTO_SHA2_256_HMAC;
	derive.session.mackeylen = sizeof(digest);
	derive.session.crid = CRYPTO_FLAG_SOFTWARE;
	derive.cd_hash = CRYPTODESC_HKDF_SHA256;
	derive.cd_rights = CRYPTODESC_RIGHT_AUTH;
	derive.cd_fd = -1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM,
	    ioctl(parent, CIOCCRYPTODESCDERIVE, &derive) == -1);
	close(parent);

	/* A derived lease remains in the named key's revocation lineage. */
	memset(&named, 0, sizeof(named));
	strlcpy(named.cd_name, name, sizeof(named.cd_name));
	strlcpy(named.cd_owner, owner, sizeof(named.cd_owner));
	named.cd_session.mac = CRYPTO_SHA2_256_HMAC;
	named.cd_session.mackeylen = sizeof(digest);
	named.cd_session.crid = CRYPTO_FLAG_SOFTWARE;
	named.cd_rights = CRYPTODESC_RIGHT_AUTH | CRYPTODESC_RIGHT_DERIVE;
	ATF_REQUIRE_EQ(0, ioctl(control, CIOCGCRYPTONAMEDKEY, &named));
	parent = lease_named(control, name, owner,
	    CRYPTODESC_RIGHT_AUTH | CRYPTODESC_RIGHT_DERIVE);
	memset(&derive, 0, sizeof(derive));
	derive.session.mac = CRYPTO_SHA2_256_HMAC;
	derive.session.mackeylen = sizeof(digest);
	derive.session.crid = CRYPTO_FLAG_SOFTWARE;
	derive.cd_hash = CRYPTODESC_HKDF_SHA256;
	derive.cd_rights = CRYPTODESC_RIGHT_AUTH;
	ATF_REQUIRE_EQ(0, ioctl(parent, CIOCCRYPTODESCDERIVE, &derive));
	child = derive.cd_fd;
	memset(&cop, 0, sizeof(cop));
	cop.op = COP_ENCRYPT;
	cop.len = sizeof(message) - 1;
	cop.src = message;
	cop.mac = digest;
	ATF_REQUIRE_EQ(0, ioctl(child, CIOCCRYPT, &cop));
	named_control(&rotate, name, owner);
	ATF_REQUIRE_EQ(0, ioctl(control, CIOCCRYPTONAMEDROTATE, &rotate));
	errno = 0;
	ATF_REQUIRE_ERRNO(EACCES, ioctl(child, CIOCCRYPT, &cop) == -1);
	close(child);
	close(parent);
	named_control(&rotate, name, owner);
	ATF_REQUIRE_EQ(0, ioctl(control, CIOCCRYPTONAMEDDELETE, &rotate));
	close(control);
}

struct cryptokey_saved_limits {
	u_int max_objects;
	u_int max_owner_objects;
};

static u_int
cryptokey_sysctl_get(const char *name)
{
	u_int value;
	size_t length;

	length = sizeof(value);
	ATF_REQUIRE_EQ(0, sysctlbyname(name, &value, &length, NULL, 0));
	ATF_REQUIRE_EQ(sizeof(value), length);
	return (value);
}

static void
cryptokey_sysctl_set(const char *name, u_int value)
{

	ATF_REQUIRE_EQ(0, sysctlbyname(name, NULL, NULL, &value,
	    sizeof(value)));
}

ATF_TC_WITH_CLEANUP(named_key_accounting_limits);
ATF_TC_HEAD(named_key_accounting_limits, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "is.exclusive", "true");
}
ATF_TC_BODY(named_key_accounting_limits, tc)
{
	static const char owner_a[] = "quota.owner.a";
	static const char owner_b[] = "quota.owner.b";
	struct cryptokey_saved_limits saved;
	struct cryptodesc_named_create create;
	struct cryptodesc_named_control control_request;
	FILE *state;
	u_int objects;
	int control;

	saved.max_objects = cryptokey_sysctl_get(
	    "kern.crypto.cryptokey_max_objects");
	saved.max_owner_objects = cryptokey_sysctl_get(
	    "kern.crypto.cryptokey_max_owner_objects");
	state = fopen("cryptokey-limits.save", "wb");
	ATF_REQUIRE(state != NULL);
	ATF_REQUIRE_EQ(1, fwrite(&saved, sizeof(saved), 1, state));
	ATF_REQUIRE_EQ(0, fclose(state));
	objects = cryptokey_sysctl_get("kern.crypto.cryptokey_objects");
	cryptokey_sysctl_set("kern.crypto.cryptokey_max_objects", objects + 2);
	cryptokey_sysctl_set("kern.crypto.cryptokey_max_owner_objects", 1);

	control = open_control();
	create_named_cbc(control, "quota-a1", owner_a,
	    CRYPTODESC_RIGHT_ENCRYPT);
	memset(&create, 0, sizeof(create));
	strlcpy(create.cd_name, "quota-a2", sizeof(create.cd_name));
	strlcpy(create.cd_owner, owner_a, sizeof(create.cd_owner));
	create.cd_session.cipher = CRYPTO_AES_CBC;
	create.cd_session.keylen = sizeof(aes_key);
	create.cd_session.crid = CRYPTO_FLAG_SOFTWARE;
	create.cd_session.ivlen = sizeof(aes_iv);
	create.cd_rights = CRYPTODESC_RIGHT_ENCRYPT;
	ATF_CHECK_ERRNO(ENOSPC,
	    ioctl(control, CIOCGCRYPTONAMEDKEY, &create) == -1);
	create_named_cbc(control, "quota-b1", owner_b,
	    CRYPTODESC_RIGHT_ENCRYPT);
	strlcpy(create.cd_name, "quota-b2", sizeof(create.cd_name));
	strlcpy(create.cd_owner, "quota.owner.c", sizeof(create.cd_owner));
	ATF_CHECK_ERRNO(ENOSPC,
	    ioctl(control, CIOCGCRYPTONAMEDKEY, &create) == -1);
	named_control(&control_request, "quota-a1", owner_a);
	ATF_REQUIRE_EQ(0,
	    ioctl(control, CIOCCRYPTONAMEDDELETE, &control_request));
	named_control(&control_request, "quota-b1", owner_b);
	ATF_REQUIRE_EQ(0,
	    ioctl(control, CIOCCRYPTONAMEDDELETE, &control_request));
	close(control);
	cryptokey_sysctl_set("kern.crypto.cryptokey_max_objects",
	    saved.max_objects);
	cryptokey_sysctl_set("kern.crypto.cryptokey_max_owner_objects",
	    saved.max_owner_objects);
}
ATF_TC_CLEANUP(named_key_accounting_limits, tc)
{
	static const char *const names[] = { "quota-a1", "quota-a2",
	    "quota-b1", "quota-b2" };
	static const char *const owners[] = { "quota.owner.a", "quota.owner.a",
	    "quota.owner.b", "quota.owner.c" };
	struct cryptokey_saved_limits saved;
	struct cryptodesc_named_control request;
	FILE *state;
	int control;
	size_t i;

	control = open("/dev/crypto", O_RDWR);
	if (control >= 0) {
		for (i = 0; i < nitems(names); i++) {
			named_control(&request, names[i], owners[i]);
			(void)ioctl(control, CIOCCRYPTONAMEDDELETE, &request);
		}
		close(control);
	}
	state = fopen("cryptokey-limits.save", "rb");
	if (state == NULL)
		return;
	if (fread(&saved, sizeof(saved), 1, state) == 1) {
		(void)sysctlbyname("kern.crypto.cryptokey_max_objects", NULL,
		    NULL, &saved.max_objects, sizeof(saved.max_objects));
		(void)sysctlbyname("kern.crypto.cryptokey_max_owner_objects", NULL,
		    NULL, &saved.max_owner_objects,
		    sizeof(saved.max_owner_objects));
	}
	(void)fclose(state);
}

ATF_TC(named_key_requires_privileged_control);
ATF_TC_HEAD(named_key_requires_privileged_control, tc)
{
	atf_tc_set_md_var(tc, "require.kmods", "cryptodev");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(named_key_requires_privileged_control, tc)
{
	struct cryptodesc_named_create create;
	int status;
	pid_t pid;

	ATF_REQUIRE_SYSCTL_INT("kern.crypto.allow_soft", 1);
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		int fd;

		if (setgid(65534) == -1 || setuid(65534) == -1)
			_exit(2);
		fd = open("/dev/crypto", O_RDWR);
		if (fd == -1)
			_exit(3);
		memset(&create, 0, sizeof(create));
		strlcpy(create.cd_name, "unprivileged-create",
		    sizeof(create.cd_name));
		strlcpy(create.cd_owner, "service.victim",
		    sizeof(create.cd_owner));
		create.cd_session.mac = CRYPTO_SHA2_256_HMAC;
		create.cd_session.mackeylen = 32;
		create.cd_session.crid = CRYPTO_FLAG_SOFTWARE;
		create.cd_rights = CRYPTODESC_RIGHT_AUTH;
		_exit(ioctl(fd, CIOCGCRYPTONAMEDKEY, &create) == -1 &&
		    errno == EPERM ? 0 : 4);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
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
	ATF_TP_ADD_TC(tp, descriptor_kinfo);
	ATF_TP_ADD_TC(tp, cbc_rights_and_metadata);
	ATF_TP_ADD_TC(tp, descriptor_metadata_and_kqueue);
	ATF_TP_ADD_TC(tp, descriptor_lifecycle);
	ATF_TP_ADD_TC(tp, digest_and_eta_rights);
	ATF_TP_ADD_TC(tp, kernel_generated_and_expiry);
	ATF_TP_ADD_TC(tp, named_key_lifecycle);
	ATF_TP_ADD_TC(tp, hkdf_opaque_derivation);
	ATF_TP_ADD_TC(tp, derive_authority_and_lineage);
	ATF_TP_ADD_TC(tp, named_key_accounting_limits);
	ATF_TP_ADD_TC(tp, derive_uses_complete_session_secret);
	ATF_TP_ADD_TC(tp, named_key_requires_privileged_control);
	ATF_TP_ADD_TC(tp, asymmetric_capabilities);
	ATF_TP_ADD_TC(tp, concurrent_descriptor_use);
	ATF_TP_ADD_TC(tp, passable_descriptor);
	ATF_TP_ADD_TC(tp, aead_rights_and_integrity);
	return (atf_no_error());
}
