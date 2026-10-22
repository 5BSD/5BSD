/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>
#include "migration_recovery_exchange.h"
#include "migration_reconcile.h"

struct endpoint {
	int fd, dirfd, error;
	struct migration_tls_credentials credentials;
	struct migration_recovery_record expected, local, peer;
};

static void *
serve(void *arg)
{
	struct endpoint *ep = arg;
	struct migration_channel channel;
	struct migration_transport xp;
	ep->error = migration_channel_init(&channel, &xp, ep->fd, true,
	    &ep->credentials, 1000);
	assert(ep->error == 0);
	ep->error = migration_recovery_exchange(&channel, &xp, ep->dirfd,
	    false, &ep->expected, &ep->local, &ep->peer);
	migration_channel_cleanup(&channel);
	close(ep->fd);
	return (NULL);
}

static void
decode_cases(const struct migration_recovery_record *expected)
{
	uint8_t wire[MIGRATION_RECOVERY_EXCHANGE_SIZE + 1] = {0};
	struct migration_recovery_record decoded = {0}, zero = {0};
	memcpy(wire, "HMX1", 4); wire[4] = 1; wire[5] = 1;
	assert(migration_recovery_encode(expected, wire + 8) == 0);
	for (size_t n = 0; n < MIGRATION_RECOVERY_EXCHANGE_SIZE; n++) {
		assert(migration_recovery_peer_decode(wire, n, expected, true, &decoded) == EPROTO);
		assert(memcmp(&decoded, &zero, sizeof(decoded)) == 0);
	}
	assert(migration_recovery_peer_decode(wire, sizeof(wire), expected, true, &decoded) == EPROTO);
	for (size_t n = 0; n < MIGRATION_RECOVERY_EXCHANGE_SIZE; n++) {
		wire[n] ^= 0x40;
		assert(migration_recovery_peer_decode(wire, sizeof(wire) - 1, expected, true, &decoded) != 0);
		assert(memcmp(&decoded, &zero, sizeof(decoded)) == 0);
		wire[n] ^= 0x40;
	}
	assert(migration_recovery_peer_decode(wire, sizeof(wire) - 1, expected, false, &decoded) == EPROTO);
	assert(migration_recovery_peer_decode(wire, sizeof(wire) - 1, expected, true, &decoded) == 0);
	assert(decoded.phase == expected->phase);
}

int
main(void)
{
	struct migration_tls_credentials src = {
	    .certificate_fd = open("source.pem", O_RDONLY),
	    .private_key_fd = open("source.key", O_RDONLY),
	    .trust_fd = open("destination.pem", O_RDONLY) };
	struct migration_tls_credentials dst = {
	    .certificate_fd = open("destination.pem", O_RDONLY),
	    .private_key_fd = open("destination.key", O_RDONLY),
	    .trust_fd = open("source.pem", O_RDONLY) };
	assert(src.certificate_fd >= 0 && src.private_key_fd >= 0 && src.trust_fd >= 0);
	assert(dst.certificate_fd >= 0 && dst.private_key_fd >= 0 && dst.trust_fd >= 0);
	int pin = open("source.pin", O_RDONLY);
	assert(pin >= 0 && read(pin, dst.peer_certificate_sha256, 32) == 32); close(pin);
	pin = open("destination.pin", O_RDONLY);
	assert(pin >= 0 && read(pin, src.peer_certificate_sha256, 32) == 32); close(pin);
	struct migration_recovery_record binding = {
	    .phase = MIGRATION_REC_SOURCE_INTENT, .destination_vmid = 8, .destination_epoch = 10 };
	struct hypertrace_session_record stopped = { .vmid = 7, .epoch = 9,
	    .stop_token = 11, .features = HYPERTRACE_SESSION_FEATURES };
	assert(hypertrace_session_record_encode(binding.session, 40, &stopped) == 0);
	memset(binding.challenge, 1, 32); memset(binding.state_digest, 2, 32);
	memcpy(binding.source_certificate_sha256, dst.peer_certificate_sha256, 32);
	memcpy(binding.destination_certificate_sha256, src.peer_certificate_sha256, 32);
	decode_cases(&binding);
	for (int mode = 0; mode < 4; mode++) {
		char directory[] = "exchange.XXXXXX";
		assert(mkdtemp(directory) != NULL);
		int dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		assert(dirfd >= 0);
		struct migration_recovery_record local = {0}, peer = {0}, zero = {0};
		struct migration_recovery_record expected = binding, durable = binding;
		struct endpoint server = { .credentials = dst, .dirfd = dirfd, .expected = binding };
		server.expected.phase = MIGRATION_REC_DEST_STAGED;
		if (mode == 1) server.expected.state_digest[0] ^= 1;
		if (mode == 2) expected.source_certificate_sha256[0] ^= 1;
		assert(migration_recovery_store_at(dirfd, &server.expected) == 0);
		if (mode != 3) {
			assert(migration_recovery_store_at(dirfd, &durable) == 0);
			durable.phase = MIGRATION_REC_SOURCE_RETIRED;
			assert(migration_recovery_store_at(dirfd, &durable) == 0);
			durable.phase = MIGRATION_REC_SOURCE_RELEASED;
			assert(migration_recovery_store_at(dirfd, &durable) == 0);
		}
		int sockets[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
		server.fd = sockets[1]; pthread_t thread;
		assert(pthread_create(&thread, NULL, serve, &server) == 0);
		struct migration_channel channel;
		struct migration_transport xp;
		assert(migration_channel_init(&channel, &xp, sockets[0], false, &src, 1000) == 0);
		int error = migration_recovery_exchange(&channel, &xp, dirfd, true,
		    &expected, &local, &peer);
		migration_channel_cleanup(&channel); close(sockets[0]);
		assert(pthread_join(thread, NULL) == 0);
		if (mode == 0) {
			assert(error == 0 && server.error == 0);
			/* The phase comes from disk, never the stale in-memory expected phase. */
			assert(local.phase == MIGRATION_REC_SOURCE_RELEASED && peer.phase == MIGRATION_REC_DEST_STAGED);
			assert(server.local.phase == peer.phase && server.peer.phase == local.phase);
			enum migration_recovery_action action = MIGRATION_REC_HOLD;
			assert(migration_recovery_reconcile(&local, &peer,
			    binding.source_certificate_sha256, binding.destination_certificate_sha256,
			    MIGRATION_REC_VM_PAUSED, &action) == 0);
			assert(action == MIGRATION_REC_REISSUE_RELEASE);
		} else {
			assert(error != 0 && server.error != 0);
			if (mode == 1) assert(server.error == ESTALE);
			if (mode == 2) assert(error == EACCES);
			if (mode == 3) assert(error == ENOENT);
			assert(memcmp(&local, &zero, sizeof(local)) == 0 && memcmp(&peer, &zero, sizeof(peer)) == 0);
			assert(memcmp(&server.local, &zero, sizeof(zero)) == 0 && memcmp(&server.peer, &zero, sizeof(zero)) == 0);
		}
		/* Plaintext and a channel/transport mismatch cannot exchange facts. */
		struct migration_transport_fd raw;
		migration_transport_fd_init(&xp, &raw, -1, 10);
		memset(&channel, 0, sizeof(channel));
		assert(migration_recovery_exchange(&channel, &xp, dirfd, true, &binding, &local, &peer) == EACCES);
		channel.secure = true;
		memcpy(channel.tls.local_certificate_sha256, binding.source_certificate_sha256, 32);
		memcpy(channel.tls.peer_certificate_sha256, binding.destination_certificate_sha256, 32);
		assert(migration_recovery_exchange(&channel, &xp, dirfd, true, &binding, &local, &peer) == EACCES);
		close(dirfd);
	}
	close(src.certificate_fd); close(src.private_key_fd); close(src.trust_fd);
	close(dst.certificate_fd); close(dst.private_key_fd); close(dst.trust_fd);
	puts("PASS: mutual-TLS durable recovery exchange, stale memory, binding mismatch, missing journal, every-byte corruption and truncation");
	return (0);
}
