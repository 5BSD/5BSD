/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/capsicum.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include "migration_tls.h"
#include "migration_channel.h"
#include "test-coverage.h"

struct endpoint {
	int fd, error;
	struct migration_tls_credentials credentials;
	uint8_t source_certificate[32], destination_certificate[32];
};
static void *
serve(void *arg)
{
	struct endpoint *ep = arg;
	struct migration_channel channel;
	struct migration_transport xp;
	uint8_t data[65536];
	ep->error = migration_channel_init(&channel, &xp, ep->fd, true, &ep->credentials, 3000);
	if (ep->error == 0) {
		assert(migration_channel_binding(&channel, false,
		    ep->source_certificate, ep->destination_certificate) == 0);
		ep->error = xp.xp_recv(xp.xp_cookie, data, sizeof(data));
		if (ep->error == 0) ep->error = xp.xp_send(xp.xp_cookie, data, sizeof(data));
		migration_channel_cleanup(&channel);
	}
	close(ep->fd);
	return (NULL);
}

int main(int argc, char **argv)
{
	bool sandbox = argc == 2 && strcmp(argv[1], "--capsicum") == 0;
	ht_test_coverage_start(sandbox ? "tls-capsicum" : "tls", false);
	struct migration_tls_credentials credentials = {
	    .certificate_fd = open("peer.pem", O_RDONLY),
	    .private_key_fd = open("peer.key", O_RDONLY),
	    .trust_fd = open("peer.pem", O_RDONLY) };
	int pin = open("pin", O_RDONLY), sockets[2];
	assert(pin >= 0 && credentials.certificate_fd >= 0 &&
	    credentials.private_key_fd >= 0 && credentials.trust_fd >= 0);
	assert(read(pin, credentials.peer_certificate_sha256, 32) == 32); close(pin);
	for (int mode = 0; mode < (sandbox ? 1 : 5); mode++) {
		struct endpoint server = { .credentials = credentials };
		struct migration_tls_credentials client = credentials;
		struct migration_channel channel;
		struct migration_transport xp;
		pthread_t thread;
		uint8_t sent[65536], received[65536];
		uint8_t source_certificate[32] = {0}, destination_certificate[32] = {0};
		for (size_t i = 0; i < sizeof(sent); i++) sent[i] = (uint8_t)i;
		assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
		if (sandbox) assert(cap_enter() == 0);
		server.fd = sockets[1];
		if (mode == 1) client.peer_certificate_sha256[0] ^= 1;
		if (mode == 2 || mode == 4) {
			client.trust_fd = open("untrusted.pem", O_RDONLY);
			assert(client.trust_fd >= 0);
		}
		if (mode == 4) {
			server.credentials.certificate_fd = open("untrusted.pem", O_RDONLY);
			server.credentials.private_key_fd = open("untrusted.key", O_RDONLY);
			assert(server.credentials.certificate_fd >= 0 && server.credentials.private_key_fd >= 0);
			int other = open("other.pin", O_RDONLY);
			assert(other >= 0 && read(other, client.peer_certificate_sha256, 32) == 32);
			close(other);
		}
		assert(pthread_create(&thread, NULL, serve, &server) == 0);
		int original = fcntl(sockets[0], F_GETFL);
		int error = migration_channel_init(&channel, &xp, sockets[0], false, &client, 3000);
		if (mode == 0 || mode == 3 || mode == 4) {
			assert(error == 0);
			assert(channel.secure && SSL_version(channel.tls.ssl) == TLS1_3_VERSION);
			assert(migration_channel_binding(&channel, true,
			    source_certificate, destination_certificate) == 0);
			assert(memcmp(source_certificate, credentials.peer_certificate_sha256, 32) == 0);
			assert(memcmp(destination_certificate, client.peer_certificate_sha256, 32) == 0);
			if (mode == 0 || mode == 4) {
				assert(xp.xp_send(xp.xp_cookie, sent, sizeof(sent)) == 0);
				assert(xp.xp_recv(xp.xp_cookie, received, sizeof(received)) == 0);
				assert(memcmp(sent, received, sizeof(sent)) == 0);
			} else {
				channel.tls.timeout_ms = 20;
				assert(xp.xp_recv(xp.xp_cookie, received, 1) == ETIMEDOUT);
			}
			migration_channel_cleanup(&channel);
		} else {
			assert(error == EACCES);
			assert(xp.xp_send == NULL && xp.xp_recv == NULL);
			assert(migration_channel_binding(&channel, true,
			    source_certificate, destination_certificate) == EACCES);
		}
		assert(fcntl(sockets[0], F_GETFL) == original);
		close(sockets[0]);
		assert(pthread_join(thread, NULL) == 0);
		if (mode == 0 || mode == 4) {
			assert(server.error == 0);
			assert(memcmp(server.source_certificate, source_certificate, 32) == 0);
			assert(memcmp(server.destination_certificate, destination_certificate, 32) == 0);
		}
		if (mode == 2 || mode == 4) close(client.trust_fd);
		if (mode == 4) {
			assert(memcmp(source_certificate, destination_certificate, 32) != 0);
			close(server.credentials.certificate_fd); close(server.credentials.private_key_fd);
		}
	}
	assert(lseek(credentials.certificate_fd, 0, SEEK_CUR) == 0);
	assert(lseek(credentials.private_key_fd, 0, SEEK_CUR) == 0);
	assert(lseek(credentials.trust_fd, 0, SEEK_CUR) == 0);
	if (sandbox) {
		close(credentials.certificate_fd); close(credentials.private_key_fd);
		close(credentials.trust_fd);
		ht_test_coverage_finish();
		return (0);
	}
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	struct migration_tls tls;
	struct migration_transport xp;
	assert(migration_tls_init(&tls, &xp, sockets[0], true, &credentials, 20) == ETIMEDOUT);
	assert(xp.xp_send == NULL && xp.xp_recv == NULL);
	assert(fchmod(credentials.private_key_fd, 0644) == 0);
	assert(migration_tls_init(&tls, &xp, sockets[0], true, &credentials, 20) == EACCES);
	assert(fchmod(credentials.private_key_fd, 0600) == 0);
	int key = credentials.private_key_fd;
	credentials.private_key_fd = open("untrusted.key", O_RDONLY);
	assert(credentials.private_key_fd >= 0);
	assert(migration_tls_init(&tls, &xp, sockets[0], true, &credentials, 20) == EACCES);
	close(credentials.private_key_fd); credentials.private_key_fd = key;
	close(sockets[0]); close(sockets[1]);
	close(credentials.certificate_fd); close(credentials.private_key_fd); close(credentials.trust_fd);
	ht_test_coverage_finish();
	return (0);
}
