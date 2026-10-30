/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_NSS_PROTOCOL_H
#define SWITCHBOARD_NSS_PROTOCOL_H
#include <sys/param.h>
#include <stdint.h>

/* Private, same-generation, native-endian pipe protocol. No pointer or fd
 * transfer. Name capacity matches SwitchBoard's manifest account fields. */
#define SB_NSS_VERSION 1
#define SB_NSS_NAME_MAX 64
#define SB_NSS_USER_NAME 1
#define SB_NSS_USER_UID 2
#define SB_NSS_GROUP_NAME 3
#define SB_NSS_GROUPS 4
struct sb_nss_request {
	uint32_t version;
	uint32_t operation;
	uint32_t id;
	char name[SB_NSS_NAME_MAX];
};
struct sb_nss_reply {
	uint32_t version;
	uint32_t error;
	uint32_t uid;
	uint32_t gid;
	uint32_t ngroups;
	char name[SB_NSS_NAME_MAX];
	char home[PATH_MAX];
	char shell[PATH_MAX];
	uint32_t groups[NGROUPS_MAX + 1];
};
/* Validation never establishes authority. owner == (uid_t)-1 disables only
 * the numeric registry-owner comparison, not structural validation. */
int sb_nss_request_valid(const struct sb_nss_request *);
int sb_nss_reply_valid(const struct sb_nss_request *, const void *, size_t,
    uid_t owner);
void sb_nss_lookup(const struct sb_nss_request *, struct sb_nss_reply *);
#endif
