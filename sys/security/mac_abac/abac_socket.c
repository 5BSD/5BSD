/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 *
 * ABAC Socket Label Management
 *
 * Handles socket label lifecycle and access checks.
 * Socket labels are inherited from the creating credential.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ucred.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"

/*
 * Socket label lifecycle
 */

/*
 * A socket holds its creator's label, a connection its listener's (none
 * for an unlabelled creator: NULL, type=unlabeled).
 */
int
abac_socket_init_label(struct label *label, int flag __unused)
{

	SLOT_SET(label, NULL);
	return (0);
}

void
abac_socket_destroy_label(struct label *label)
{

	abac_label_free(SLOT(label));
	SLOT_SET(label, NULL);
}

void
abac_socket_copy_label(struct label *src, struct label *dest)
{

	if (src == NULL || dest == NULL)
		return;
	abac_label_share(dest, abac_slot, SLOT(src));
}

/*
 * Socket creation - inherit label from creating credential
 */
void
abac_socket_create(struct ucred *cred, struct socket *so,
    struct label *solabel)
{

	if (cred == NULL || cred->cr_label == NULL || solabel == NULL)
		return;
	abac_label_share(solabel, abac_slot, SLOT(cred->cr_label));
}

/*
 * New connection on listening socket - inherit label from parent
 */
void
abac_socket_newconn(struct socket *oldso, struct label *oldsolabel,
    struct socket *newso, struct label *newsolabel)
{

	if (oldsolabel == NULL || newsolabel == NULL)
		return;
	abac_label_share(newsolabel, abac_slot, SLOT(oldsolabel));
}

/*
 * Socket access checks
 *
 * For socket operations, the subject is the process credential and
 * the object is the socket label. This allows rules like:
 *   deny connect type=untrusted -> *
 *   allow bind type=webserver -> *
 */

int
abac_socket_check_accept(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_LIVE(ABAC_OP_ACCEPT);
	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_ACCEPT, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_socket_check_bind(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_LIVE(ABAC_OP_BIND);
	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_BIND, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_socket_check_connect(struct ucred *cred, struct socket *so,
    struct label *solabel, struct sockaddr *sa)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_LIVE(ABAC_OP_CONNECT);
	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_CONNECT, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_socket_check_listen(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_LIVE(ABAC_OP_LISTEN);
	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_LISTEN, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_socket_check_receive(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_LIVE(ABAC_OP_RECEIVE);
	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_RECEIVE, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

int
abac_socket_check_send(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_LIVE(ABAC_OP_SEND);
	ABAC_CHECK_ENABLED();

	/* Get subject label from credential */
	if (cred == NULL || cred->cr_label == NULL)
		return (0);
	subj = SLOT(cred->cr_label);
	if (subj == NULL)
		subj = &abac_default_subject;

	/* Get object label from socket */
	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules */
	error = abac_rules_check(cred, subj, obj, ABAC_OP_SEND, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}

/*
 * Socketpeer label lifecycle
 *
 * The socketpeer label represents the remote end of a connection.
 * For Unix domain sockets, this is the connecting process's label.
 * For TCP connections, this can be set from incoming packets or
 * propagated from accept().
 *
 * This enables rules like:
 *   deny accept * -> type=untrusted   # reject connections from untrusted peers
 *   allow connect type=client -> type=server
 */

/* A peer label is set from the peer; no rule reads it. */
int
abac_socketpeer_init_label(struct label *label, int flag __unused)
{

	SLOT_SET(label, NULL);
	return (0);
}

void
abac_socketpeer_destroy_label(struct label *label)
{

	abac_label_free(SLOT(label));
	SLOT_SET(label, NULL);
}

/*
 * Set peer label from incoming mbuf (network packet).
 *
 * This is called when a packet arrives and we need to set the peer
 * label from the mbuf's label. For IP-based sockets, the mbuf label
 * typically comes from the network layer (if labeled networking is used).
 *
 * For most use cases without labeled networking, this copies an empty label.
 */
void
abac_socketpeer_set_from_mbuf(struct mbuf *m, struct label *mlabel,
    struct socket *so, struct label *sopeerlabel)
{

	/* mac_abac labels no mbuf: the peer keeps what it has. */
	if (mlabel == NULL || sopeerlabel == NULL || SLOT(mlabel) == NULL)
		return;
	abac_label_share(sopeerlabel, abac_slot, SLOT(mlabel));
}

/*
 * Set peer label from another socket (accept).
 *
 * When a connection is accepted, the new socket's peer label is set
 * from the connecting socket's label. This is the primary mechanism
 * for Unix domain socket peer labeling.
 *
 * For TCP accept(), oldso is the connecting socket and newso is the
 * newly accepted socket. The peer label of newso gets the label of oldso.
 */
void
abac_socketpeer_set_from_socket(struct socket *oldso,
    struct label *oldsolabel, struct socket *newso,
    struct label *newsopeerlabel)
{

	if (oldsolabel == NULL || newsopeerlabel == NULL)
		return;
	abac_label_share(newsopeerlabel, abac_slot, SLOT(oldsolabel));
}

/*
 * Check if a packet can be delivered to a socket.
 *
 * This hook is called when a network packet (mbuf) is about to be
 * delivered to a socket. It allows policies to filter incoming packets
 * based on their label (if labeled networking is in use) versus the
 * socket's label.
 *
 * This enables rules like:
 *   deny deliver type=external -> type=internal
 *   allow deliver type=trusted -> *
 *
 * Note: Without labeled networking (CIPSO, IPSEC with labels), the mbuf
 * label will typically be empty, so this hook is mostly useful when
 * combined with network labeling.
 */
int
abac_socket_check_deliver(struct socket *so, struct label *solabel,
    struct mbuf *m, struct label *mlabel)
{
	struct abac_label *subj, *obj;
	int error;

	ABAC_CHECK_LIVE(ABAC_OP_DELIVER);
	ABAC_CHECK_ENABLED();

	/*
	 * Subject is the packet (mbuf) label - the incoming data.
	 * Object is the socket label - the destination.
	 */
	if (mlabel == NULL)
		return (0);
	subj = SLOT(mlabel);
	if (subj == NULL)
		subj = &abac_default_subject;

	if (solabel == NULL)
		return (0);
	obj = SLOT(solabel);
	if (obj == NULL)
		obj = &abac_default_object;

	/* Evaluate rules - no credential available, packet delivery */
	error = abac_rules_check(NULL, subj, obj, ABAC_OP_DELIVER, NULL);

	/* In permissive mode, log but allow */
	if (error != 0 && abac_mode == ABAC_MODE_PERMISSIVE)
		return (0);

	return (error);
}
