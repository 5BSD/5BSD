/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_SCOPE_TARGET_H
#define SWITCHBOARD_SCOPE_TARGET_H
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Explicit control target syntax is user:<uid>:<label>. Authority to select
 * a foreign UID must already have been verified by the control dispatcher. */
static inline bool
sb_control_personal_target(const char *target, uid_t caller, bool is_operator,
    uid_t *owner, const char **label)
{
	const char *p;
	uintmax_t value = 0;

	if (strncmp(target, "user:", 5) != 0)
		return (false);
	p = target + 5;
	if (*p < '0' || *p > '9')
		return (false);
	do {
		unsigned digit = (unsigned)(*p - '0');

		if (value > (UINTMAX_MAX - digit) / 10)
			return (false);
		value = value * 10 + digit;
		p++;
	} while (*p >= '0' && *p <= '9');
	if (*p != ':' || p[1] == '\0' || (uid_t)value == (uid_t)-1 ||
	    (uintmax_t)(uid_t)value != value ||
	    (!is_operator && (uid_t)value != caller))
		return (false);
	*owner = (uid_t)value;
	*label = p + 1;
	return (true);
}
#endif
