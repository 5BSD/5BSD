/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "vsock_migration_state.c"
#include "migration_vsock_bundle.c"

ATF_TC_WITHOUT_HEAD(bundle_roundtrip_and_rejects_corruption);
ATF_TC_BODY(bundle_roundtrip_and_rejects_corruption, tc)
{
	const struct vsock_migration_conn_state conn = {
		.local_port = 1024,
		.guest_port = 5555,
		.type = VSOCK_MIGRATION_TYPE_STREAM,
		.state = VSOCK_MIGRATION_CONN_ESTABLISHED,
		.buf_alloc = VSOCK_MIGRATION_MAX_BUFFER,
		.peer_buf_alloc = VSOCK_MIGRATION_MAX_PEER_BUFFER,
	};
	struct migration_vsock_bundle_item items[2] = { 0 }, decoded[2];
	uint8_t empty[VSOCK_MIGRATION_TABLE_HEADER_SIZE];
	uint8_t *table, *bundle;
	size_t table_len, bundle_len;
	uint32_t count, endpoints;

	(void)tc;
	ATF_REQUIRE_EQ(vsock_migration_table_size(&conn, 1, &table_len), 0);
	table = malloc(table_len);
	ATF_REQUIRE(table != NULL);
	ATF_REQUIRE_EQ(vsock_migration_table_encode(&conn, 1, table,
	    table_len), 0);
	ATF_REQUIRE_EQ(vsock_migration_table_encode(NULL, 0, empty,
	    sizeof(empty)), 0);
	strlcpy(items[0].name, "pci.0.5.0", sizeof(items[0].name));
	items[0].table = table;
	items[0].table_len = table_len;
	items[0].endpoint_count = 1;
	strlcpy(items[1].name, "pci.0.6.0", sizeof(items[1].name));
	items[1].table = empty;
	items[1].table_len = sizeof(empty);
	ATF_REQUIRE_EQ(migration_vsock_bundle_size(items, 2,
	    &bundle_len), 0);
	bundle = malloc(bundle_len);
	ATF_REQUIRE(bundle != NULL);
	ATF_REQUIRE_EQ(migration_vsock_bundle_encode(items, 2, bundle,
	    bundle_len), 0);
	memset(decoded, 0xa5, sizeof(decoded));
	count = endpoints = UINT32_MAX;
	ATF_REQUIRE_EQ(migration_vsock_bundle_decode(bundle, bundle_len,
	    decoded, 2, &count, &endpoints), 0);
	ATF_CHECK_EQ(count, 2U);
	ATF_CHECK_EQ(endpoints, 1U);
	ATF_CHECK_EQ(strcmp(decoded[0].name, "pci.0.5.0"), 0);
	ATF_CHECK_EQ(strcmp(decoded[1].name, "pci.0.6.0"), 0);
	ATF_CHECK_EQ(decoded[0].endpoint_count, 1U);
	ATF_CHECK_EQ(decoded[1].endpoint_count, 0U);
	ATF_CHECK_EQ(memcmp(decoded[0].table, table, table_len), 0);
	ATF_CHECK_EQ(migration_vsock_bundle_decode(bundle, bundle_len - 1,
	    decoded, 2, &count, &endpoints), EINVAL);
	ATF_CHECK_EQ(count, 2U);
	ATF_CHECK_EQ(endpoints, 1U);
	/* The wire's endpoint count must match its validated state table. */
	le32enc(bundle + BUNDLE_HEADER_SIZE + 44, 2);
	ATF_CHECK_EQ(migration_vsock_bundle_decode(bundle, bundle_len,
	    decoded, 2, &count, &endpoints), EINVAL);
	ATF_CHECK_EQ(count, 2U);
	le32enc(bundle + BUNDLE_HEADER_SIZE + 44, 1);
	/* Duplicate PCI identities cannot bind two different relay tables. */
	memcpy(bundle + BUNDLE_HEADER_SIZE + BUNDLE_ITEM_SIZE + table_len,
	    items[0].name, MIGRATION_VSOCK_BUNDLE_NAME);
	ATF_CHECK_EQ(migration_vsock_bundle_decode(bundle, bundle_len,
	    decoded, 2, &count, &endpoints), EINVAL);
	memcpy(items[1].name, items[0].name, sizeof(items[1].name));
	ATF_CHECK_EQ(migration_vsock_bundle_size(items, 2,
	    &bundle_len), EINVAL);
	free(bundle);
	free(table);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, bundle_roundtrip_and_rejects_corruption);
	return (atf_no_error());
}
