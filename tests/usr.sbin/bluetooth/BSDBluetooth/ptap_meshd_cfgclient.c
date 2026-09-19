/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */

/* Test-only translation-unit wrapper for cfg_result() status formatting. */
#include "meshd_cfgclient.c"

int ptap_meshd_cfg_result(struct meshd_node *, const char *, uint16_t,
    const uint8_t *, size_t, char *, size_t);

int
ptap_meshd_cfg_result(struct meshd_node *nd, const char *verb, uint16_t dst,
    const uint8_t *status, size_t status_len, char *reply, size_t reply_max)
{
	struct mesh_mgr_txn saved;
	int ret;

	if (nd == NULL || status_len > sizeof(nd->cfg_txn.status))
		return (-1);
	saved = nd->cfg_txn;
	memset(&nd->cfg_txn, 0, sizeof(nd->cfg_txn));
	nd->cfg_txn.state = status == NULL ? MESH_MGR_TXN_WAITING :
	    MESH_MGR_TXN_COMPLETE;
	if (status != NULL && status_len != 0)
		memcpy(nd->cfg_txn.status, status, status_len);
	nd->cfg_txn.status_len = status_len;
	ret = cfg_result(nd, verb, dst, reply, reply_max);
	nd->cfg_txn = saved;
	return (ret);
}
