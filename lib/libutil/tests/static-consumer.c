/* SPDX-License-Identifier: BSD-2-Clause */
/* Link-only credential reference; never invoke setusercontext(). */
#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <pwd.h>
#include <libutil.h>
#include <login_cap.h>

#ifdef REFERENCE_LOGIN_CONTEXT
static int (*volatile context_function)(login_cap_t *, const struct passwd *,
    uid_t, unsigned int) = setusercontext;
#endif

int
main(void)
{
#ifdef REFERENCE_LOGIN_CONTEXT
	return (context_function == NULL);
#else
	int64_t value;

	return (expand_number("1536", &value) != 0 || value != 1536);
#endif
}
