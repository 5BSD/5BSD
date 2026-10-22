/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include "migration_tls.h"

#define MIGRATION_TLS_PEM_LIMIT (1024 * 1024)

static void
migration_tls_bio_free(BIO *bio)
{
	char *data;
	long length;
	if (bio == NULL) return;
	length = BIO_get_mem_data(bio, &data);
	if (length > 0) explicit_bzero(data, (size_t)length);
	BIO_free(bio);
}

/* pread leaves the caller's descriptor offset unchanged. No password prompt
 * or path lookup is permitted inside a sandboxed migration operation. */
static BIO *
migration_tls_pem(int fd, bool secret)
{
	struct stat st;
	uint8_t buffer[4096];
	off_t offset = 0;
	BIO *bio;
	ssize_t count;

	if (fstat(fd, &st) != 0) return (NULL);
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    st.st_size > MIGRATION_TLS_PEM_LIMIT ||
	    (secret && (st.st_uid != geteuid() || (st.st_mode & 077) != 0))) {
		errno = EACCES;
		return (NULL);
	}
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) { errno = ENOMEM; return (NULL); }
	while (offset < st.st_size) {
		size_t amount = (size_t)(st.st_size - offset);
		if (amount > sizeof(buffer)) amount = sizeof(buffer);
		count = pread(fd, buffer, amount, offset);
		if (count < 0 && errno == EINTR) continue;
		if (count <= 0 || BIO_write(bio, buffer, (int)count) != count) {
			int error = count < 0 ? errno : EIO;
			explicit_bzero(buffer, sizeof(buffer));
			migration_tls_bio_free(bio);
			errno = error;
			return (NULL);
		}
		offset += count;
	}
	explicit_bzero(buffer, sizeof(buffer));
	BIO_set_mem_eof_return(bio, 0);
	return (bio);
}

static int
migration_tls_no_password(char *buf, int size, int rwflag, void *arg)
{
	(void)buf; (void)size; (void)rwflag; (void)arg;
	return (0);
}

static int
migration_tls_certificates(SSL_CTX *ctx, int fd, bool trust)
{
	BIO *bio = migration_tls_pem(fd, false);
	X509 *certificate;
	unsigned count = 0;
	int error = 0;

	if (bio == NULL) return (errno);
	for (;;) {
		ERR_clear_error();
		certificate = PEM_read_bio_X509(bio, NULL, migration_tls_no_password, NULL);
		if (certificate == NULL) {
			if (count == 0 || !BIO_eof(bio) ||
			    ERR_GET_REASON(ERR_peek_last_error()) != PEM_R_NO_START_LINE)
				error = EINVAL;
			break;
		}
		if (trust) {
			if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), certificate) != 1)
				error = EINVAL;
		} else if (count == 0) {
			if (SSL_CTX_use_certificate(ctx, certificate) != 1) error = EINVAL;
		} else if (SSL_CTX_add_extra_chain_cert(ctx, certificate) == 1) {
			certificate = NULL; /* context owns this reference */
		} else error = EINVAL;
		X509_free(certificate);
		if (error != 0) break;
		count++;
	}
	migration_tls_bio_free(bio);
	ERR_clear_error();
	return (error);
}

static int64_t
migration_tls_now(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return (-1);
	return ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
}

static int
migration_tls_wait(struct migration_tls *tls, int ssl_error, int64_t deadline)
{
	struct pollfd pfd = { .fd = tls->fd };
	int64_t now, left;
	int result;

	if (ssl_error == SSL_ERROR_ZERO_RETURN) return (ECONNRESET);
	if (ssl_error == SSL_ERROR_SYSCALL) return (errno != 0 ? errno : ECONNRESET);
	if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
		return (SSL_get_verify_result(tls->ssl) != X509_V_OK ? EACCES : EPROTO);
	pfd.events = ssl_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
	for (;;) {
		now = migration_tls_now();
		if (now < 0) return (errno);
		left = deadline - now;
		if (left <= 0) return (ETIMEDOUT);
		result = poll(&pfd, 1, left > INT_MAX ? INT_MAX : (int)left);
		if (result < 0 && errno == EINTR) continue;
		if (result < 0) return (errno);
		if (result == 0) return (ETIMEDOUT);
		if (pfd.revents & POLLNVAL) return (EBADF);
		/* SSL handles EOF/alerts after readiness, including POLLHUP. */
		return (0);
	}
}

static int
migration_tls_transfer(struct migration_tls *tls, void *buffer, size_t length,
    bool writing)
{
	uint8_t *cursor = buffer;
	int64_t deadline = migration_tls_now(), now;
	size_t done;
	int result, error;
	if (deadline < 0) return (errno);
	deadline += tls->timeout_ms;
	while (length != 0) {
		now = migration_tls_now();
		if (now < 0) return (errno);
		if (now >= deadline) return (ETIMEDOUT);
		ERR_clear_error(); errno = 0;
		result = writing ? SSL_write_ex(tls->ssl, cursor, length, &done) :
		    SSL_read_ex(tls->ssl, cursor, length, &done);
		if (result == 1) {
			if (done == 0 || done > length) return (EPROTO);
			cursor += done; length -= done;
			continue;
		}
		error = migration_tls_wait(tls, SSL_get_error(tls->ssl, result), deadline);
		if (error != 0) return (error);
	}
	return (0);
}

static int
migration_tls_send(void *cookie, const void *buffer, size_t length)
{
	return (migration_tls_transfer(cookie, __DECONST(void *, buffer), length, true));
}

static int
migration_tls_recv(void *cookie, void *buffer, size_t length)
{
	return (migration_tls_transfer(cookie, buffer, length, false));
}

void
migration_tls_cleanup(struct migration_tls *tls)
{
	if (tls == NULL) return;
	SSL_free(tls->ssl);
	SSL_CTX_free(tls->context);
	if (tls->fd >= 0 && tls->original_flags >= 0)
		(void)fcntl(tls->fd, F_SETFL, tls->original_flags);
	memset(tls, 0, sizeof(*tls));
	tls->fd = tls->original_flags = -1;
}

int
migration_tls_init(struct migration_tls *tls, struct migration_transport *xp,
    int fd, bool server, const struct migration_tls_credentials *credentials,
    int timeout_ms)
{
	BIO *key_bio = NULL;
	EVP_PKEY *key = NULL;
	X509 *peer = NULL;
	uint8_t digest[EVP_MAX_MD_SIZE];
	unsigned digest_length;
	int64_t deadline;
	int error = EINVAL, result, one = 1;

	if (tls == NULL || xp == NULL || credentials == NULL || timeout_ms <= 0)
		return (EINVAL);
	memset(xp, 0, sizeof(*xp));
	memset(tls, 0, sizeof(*tls));
	tls->fd = tls->original_flags = -1;
	if (memcmp(credentials->peer_certificate_sha256,
	    (const uint8_t[32]){0}, 32) == 0) return (EINVAL);
	if (OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) != 1) return (EIO);
	tls->context = SSL_CTX_new(TLS_method());
	if (tls->context == NULL) { error = ENOMEM; goto fail; }
	if (SSL_CTX_set_min_proto_version(tls->context, TLS1_3_VERSION) != 1) goto fail;
	SSL_CTX_set_verify(tls->context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_verify_depth(tls->context, 8);
	SSL_CTX_set_session_cache_mode(tls->context, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_num_tickets(tls->context, 0);
	error = migration_tls_certificates(tls->context, credentials->trust_fd, true);
	if (error != 0) goto fail;
	error = migration_tls_certificates(tls->context, credentials->certificate_fd, false);
	if (error != 0) goto fail;
	key_bio = migration_tls_pem(credentials->private_key_fd, true);
	if (key_bio == NULL) { error = errno; goto fail; }
	key = PEM_read_bio_PrivateKey(key_bio, NULL, migration_tls_no_password, NULL);
	if (key == NULL || SSL_CTX_use_PrivateKey(tls->context, key) != 1 ||
	    SSL_CTX_check_private_key(tls->context) != 1) { error = EACCES; goto fail; }
	migration_tls_bio_free(key_bio); key_bio = NULL;
	EVP_PKEY_free(key); key = NULL;
	tls->fd = fd;
	tls->original_flags = fcntl(fd, F_GETFL);
	if (tls->original_flags < 0 || fcntl(fd, F_SETFL,
	    tls->original_flags | O_NONBLOCK) != 0 ||
	    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one)) != 0) {
		error = errno; goto fail;
	}
	tls->timeout_ms = timeout_ms;
	tls->ssl = SSL_new(tls->context);
	if (tls->ssl == NULL || SSL_set_fd(tls->ssl, fd) != 1) { error = EIO; goto fail; }
	if (server) SSL_set_accept_state(tls->ssl); else SSL_set_connect_state(tls->ssl);
	deadline = migration_tls_now();
	if (deadline < 0) { error = errno; goto fail; }
	deadline += timeout_ms;
	for (;;) {
		ERR_clear_error(); errno = 0;
		result = SSL_do_handshake(tls->ssl);
		if (result == 1) break;
		error = migration_tls_wait(tls, SSL_get_error(tls->ssl, result), deadline);
		if (error != 0) goto fail;
	}
	peer = SSL_get1_peer_certificate(tls->ssl);
	if (peer == NULL || SSL_get_verify_result(tls->ssl) != X509_V_OK ||
	    X509_digest(peer, EVP_sha256(), digest, &digest_length) != 1 ||
	    digest_length != 32 ||
	    CRYPTO_memcmp(digest, credentials->peer_certificate_sha256, 32) != 0) {
		error = EACCES; goto fail;
	}
	memcpy(tls->peer_certificate_sha256, digest, 32);
	if (SSL_get_certificate(tls->ssl) == NULL ||
	    X509_digest(SSL_get_certificate(tls->ssl), EVP_sha256(), digest,
	    &digest_length) != 1 || digest_length != 32) {
		error = EACCES; goto fail;
	}
	memcpy(tls->local_certificate_sha256, digest, 32);
	X509_free(peer);
	xp->xp_send = migration_tls_send;
	xp->xp_recv = migration_tls_recv;
	xp->xp_cookie = tls;
	return (0);
fail:
	X509_free(peer);
	EVP_PKEY_free(key);
	migration_tls_bio_free(key_bio);
	migration_tls_cleanup(tls);
	ERR_clear_error();
	return (error);
}
