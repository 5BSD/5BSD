/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* White-box parser probes for the persistent Mesh node-state frame. */
#include "meshd_persist.c"

int ptap_meshd_persist_decode_sweep(const struct meshd_node *);

int
ptap_meshd_persist_decode_sweep(const struct meshd_node *source)
{
	struct meshd_persist ps;
	struct meshd_node tmp;
	struct cur c;
	uint8_t *body, *work;
	uint32_t high_water;
	size_t body_len, i;
	int decoded, fd;

	if (source == NULL || source->self == NULL)
		return (-1);
	body = calloc(1, MESHD_PERSIST_BODY_MAX);
	work = calloc(1, MESHD_PERSIST_BODY_MAX);
	if (body == NULL || work == NULL) {
		free(body);
		free(work);
		return (-1);
	}

	memset(&ps, 0, sizeof(ps));
	ps.reserved = source->self->seq + MESHD_PERSIST_SEQ_BLOCK;

	/* Small persistence invariants are otherwise masked by the full decoder:
	 * exercise both sides of their address, extent, and schema boundaries. */
	if (!persist_version_supported(MESHD_PERSIST_VERSION) ||
	    persist_version_supported(2) ||
	    persist_version_supported(1) ||
	    persist_version_supported(MESHD_PERSIST_VERSION + 1) ||
	    !persist_unicast_block_valid(1, 1) ||
	    !persist_unicast_block_valid(0x7fff, 1) ||
	    persist_unicast_block_valid(0, 1) ||
	    persist_unicast_block_valid(0x7fff, 2) ||
	    !persist_blocks_overlap(1, 2, 2, 2) ||
	    persist_blocks_overlap(1, 1, 2, 1)) {
		free(body);
		free(work);
		return (-1);
	}
	if (persist_crc32(0, "123456789", 9) != 0xcbf43926u ||
	    persist_crc32(0, "", 0) != 0 ||
	    persist_crc32(0x12345678u, "mesh", 4) ==
	    persist_crc32(0x12345678u, "mesH", 4)) {
		free(body);
		free(work);
		return (-1);
	}
	/* Atomic manager persistence must flush each of the relative, absolute,
	 * and invalid-parent directory forms. */
	if (fsync_parent_dir("node.state") != 0 ||
	    fsync_parent_dir("/tmp/node.state") != 0 ||
	    fsync_parent_dir("/node.state") != 0 ||
	    fsync_parent_dir("/definitely-missing-parent/node.state") == 0) {
		free(body);
		free(work);
		return (-1);
	}
	memset(&c, 0, sizeof(c));
	c.buf = body;
	c.len = MESHD_PERSIST_BODY_MAX;
	encode_body(&c, &ps, source);
	if (c.err) {
		free(body);
		free(work);
		return (-1);
	}
	body_len = c.off;

	/* Exercise the cursor's sticky overflow/underflow behavior directly. */
	memset(&c, 0, sizeof(c));
	c.buf = work;
	c.len = 1;
	put_u64(&c, 1);
	put_u8(&c, 1);
	memset(&c, 0, sizeof(c));
	c.rbuf = body;
	c.len = 1;
	(void)get_u64(&c);
	(void)get_u8(&c);

	/* Cover short-I/O helpers and both node re-homing outcomes. */
	fd = open("/dev/null", O_RDONLY);
	if (fd >= 0) {
		(void)read_all(fd, work, 1);
		(void)close(fd);
	}
	fd = open("/dev/null", O_WRONLY);
	if (fd >= 0) {
		(void)write_all(fd, body, body_len);
		(void)close(fd);
	}
	node_decode_init(&tmp);
	node_rehome_sim(&tmp, -1);
	meshd_node_fini(&tmp);

	/*
	 * Mutate each byte independently.  Every trial begins with a known-good
	 * serialization, so failures identify a single field and drive the actual
	 * validation and cleanup paths without relying on private byte offsets.
	 */
	decoded = 0;
	for (i = 0; i < body_len; i++) {
		/* Include small valid-looking counters as well as boundary values:
		 * count and enum fields often reject 1/3/7 differently from 0xff. */
		uint8_t values[] = { 0xff, 0x80, 0x7f, 0x03, 0x02, 0x01, 0x00 };
		size_t j;

		for (j = 0; j < sizeof(values) / sizeof(values[0]); j++) {
			if (body[i] == values[j])
				continue;
			memcpy(work, body, body_len);
			work[i] = values[j];
			node_decode_init(&tmp);
			memset(&c, 0, sizeof(c));
			c.rbuf = work;
			c.len = body_len;
			if (decode_body(&c, &tmp, &high_water) == 0)
				decoded++;
			meshd_node_fini(&tmp);
		}
	}

	/* A final truncation reaches the decoder's terminal cursor check. */
	node_decode_init(&tmp);
	memset(&c, 0, sizeof(c));
	c.rbuf = body;
	c.len = body_len - 1;
	(void)decode_body(&c, &tmp, &high_water);
	meshd_node_fini(&tmp);
	free(body);
	free(work);
	return (decoded);
}
