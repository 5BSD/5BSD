/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_INSTALLATION_QUERY_H
#define SWITCHBOARD_INSTALLATION_QUERY_H
struct channel_message;
struct sl_query_cache;
/* Shared by query replies and cleanup in the single-threaded manager. */
struct sl_query_cache *svc_installation_query_cache(void);
/* Used only on the authenticated service control channel. Does not free request. */
int svc_installation_query_reply(const char *, struct channel_message *);
#endif
