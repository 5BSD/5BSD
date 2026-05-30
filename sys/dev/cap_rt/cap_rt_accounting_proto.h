/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_accounting — wire protocol for the accounting service.
 *
 * External resource ledger and enforcement via an attached procdesc fd.
 * If no fd is attached, the operation targets the caller (self).
 */

#ifndef _DEV_CAP_RT_CAP_RT_ACCOUNTING_PROTO_H_
#define _DEV_CAP_RT_CAP_RT_ACCOUNTING_PROTO_H_

/* Operations */
#define	ACCT_OP_CHARGE		1	/* racct_add: debit resource */
#define	ACCT_OP_RELEASE		2	/* racct_sub: credit resource */
#define	ACCT_OP_SET		3	/* racct_set: absolute value */
#define	ACCT_OP_ADD_RULE	4	/* add rctl enforcement rule */
#define	ACCT_OP_REMOVE_RULE	5	/* remove rctl enforcement rule */
#define	ACCT_OP_GET_RULES	6	/* query active enforcement rules */

/* Status codes */
#define	ACCT_STATUS_OK		0
#define	ACCT_STATUS_ERR		1
#define	ACCT_STATUS_DEAD	2	/* process has exited */
#define	ACCT_STATUS_DENIED	3	/* would exceed limit */
#define	ACCT_STATUS_EPERM	4	/* permission denied */

/* Request: charge / release / set */
struct acct_charge_request {
	uint32_t	op;		/* ACCT_OP_CHARGE/RELEASE/SET */
	uint32_t	resource;	/* RACCT_* constant */
	uint64_t	amount;
} __packed;

/* RCTL actions — mirrors kernel rctl but simplified */
#define	ACCT_RULE_DENY		1	/* fail allocation */
#define	ACCT_RULE_LOG		2	/* log violation */
#define	ACCT_RULE_THROTTLE	3	/* sleep process */
#define	ACCT_RULE_SIGNAL	4	/* send signal */

/* Request: add rctl rule */
struct acct_rule_request {
	uint32_t	op;		/* ACCT_OP_ADD_RULE / ACCT_OP_REMOVE_RULE */
	uint32_t	resource;	/* RACCT_* constant */
	uint32_t	action;		/* ACCT_RULE_* */
	uint32_t	signal;		/* signal number if action==SIGNAL */
	uint64_t	limit;		/* trigger threshold */
} __packed;

/* Reply: charge / release / set / add_rule / remove_rule */
struct acct_reply {
	uint32_t	status;
	uint32_t	_pad;
} __packed;

/* Reply: get_rules */
#define	ACCT_MAX_RULES	16

struct acct_rule_entry {
	uint32_t	resource;
	uint32_t	action;
	uint32_t	signal;
	uint32_t	_pad;
	uint64_t	limit;
} __packed;

struct acct_rules_reply {
	uint32_t	status;
	uint32_t	nrules;
	struct acct_rule_entry rules[ACCT_MAX_RULES];
} __packed;

#endif /* _DEV_CAP_RT_CAP_RT_ACCOUNTING_PROTO_H_ */
