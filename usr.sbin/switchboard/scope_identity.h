/* SPDX-License-Identifier: BSD-2-Clause */
/* Installation namespaces are independent of software signing identity. */
#ifndef SWITCHBOARD_SCOPE_IDENTITY_H
#define SWITCHBOARD_SCOPE_IDENTITY_H
#include <sys/types.h>
#include <stdbool.h>

struct sb_install_scope {
	bool personal;
	uid_t owner;
};
static inline struct sb_install_scope
sb_scope_from_registry_owner(uid_t owner)
{
	return ((struct sb_install_scope){ owner != (uid_t)-1, owner });
}
static inline bool
sb_scope_equal(struct sb_install_scope a, struct sb_install_scope b)
{
	return (a.personal == b.personal && (!a.personal || a.owner == b.owner));
}
/* GLOBAL names remain reserved against personal shadows. Personal names only
 * collide within one authenticated owner's namespace. This is a collision
 * relation, not identity equality: never use it for replacement or removal. */
static inline bool
sb_scope_names_conflict(struct sb_install_scope a, struct sb_install_scope b)
{
	return (!a.personal || !b.personal || a.owner == b.owner);
}
/* Select a personal route only from kernel-stamped transport credentials.
 * Signature presence/software authority and inherited channel metadata are
 * independent; unsigned UNIX clients still have authenticated UNIX owners.
 * No root bypass: UID 0 is not UID 1001. Existing global visibility/attribute
 * checks must still run separately for global endpoints. */
static inline bool
sb_scope_personal_access(struct sb_install_scope target,
    bool kernel_sender_present, uid_t kernel_sender_uid)
{
	return (target.personal && kernel_sender_present &&
	    kernel_sender_uid != (uid_t)-1 && target.owner == kernel_sender_uid);
}
#endif
