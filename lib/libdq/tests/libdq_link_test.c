/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * libdq.so.1 records every shared library it needs.  dq_serve_state_create()
 * and the serve loop start threads, so the library needs libthr; a program
 * linked with -ldq alone must load and run without adding -lpthread.  This
 * program is deliberately linked with neither libdq nor libthr: it opens
 * libdq.so.1 with dlopen(3) the way such a program's start-up would load it.
 */

#include <sys/param.h>

#include <atf-c.h>
#include <dlfcn.h>
#include <link.h>
#include <stdbool.h>
#include <string.h>

#define	LIBDQ	"libdq.so.1"
#define	LIBTHR	"libthr.so.3"

/* True if the dynamic section of lm names soname in a DT_NEEDED entry. */
static bool
needs(const struct link_map *lm, const char *soname)
{
	const Elf_Dyn *dyn;
	const char *strtab;

	strtab = NULL;
	for (dyn = lm->l_ld; dyn->d_tag != DT_NULL; dyn++)
		if (dyn->d_tag == DT_STRTAB)
			strtab = (const char *)(lm->l_base + dyn->d_un.d_ptr);
	ATF_REQUIRE_MSG(strtab != NULL, "%s has no DT_STRTAB", lm->l_name);
	for (dyn = lm->l_ld; dyn->d_tag != DT_NULL; dyn++)
		if (dyn->d_tag == DT_NEEDED &&
		    strcmp(strtab + dyn->d_un.d_val, soname) == 0)
			return (true);
	return (false);
}

ATF_TC_WITHOUT_HEAD(needed_libthr);
ATF_TC_BODY(needed_libthr, tc)
{
	struct link_map *lm;
	void *h;

	ATF_REQUIRE_MSG(dlopen(LIBTHR, RTLD_LAZY | RTLD_NOLOAD) == NULL,
	    "%s is already loaded; the test proves nothing", LIBTHR);
	h = dlopen(LIBDQ, RTLD_LAZY | RTLD_LOCAL);
	ATF_REQUIRE_MSG(h != NULL, "dlopen(%s): %s", LIBDQ, dlerror());
	ATF_REQUIRE(dlinfo(h, RTLD_DI_LINKMAP, &lm) == 0);
	ATF_CHECK_MSG(needs(lm, LIBTHR), "%s has no DT_NEEDED for %s",
	    LIBDQ, LIBTHR);
}

ATF_TC_WITHOUT_HEAD(dlopen_now_resolves);
ATF_TC_BODY(dlopen_now_resolves, tc)
{
	void *h;

	/*
	 * RTLD_NOW binds every symbol the library references, as a program
	 * linked with -z now (or LD_BIND_NOW) does at start; an undeclared
	 * dependency shows as "Undefined symbol pthread_create".
	 */
	h = dlopen(LIBDQ, RTLD_NOW | RTLD_LOCAL);
	ATF_REQUIRE_MSG(h != NULL, "dlopen(%s): %s", LIBDQ, dlerror());
	ATF_CHECK(dlsym(h, "dq_serve_state_create") != NULL);
	ATF_CHECK(dlsym(h, "dq_serve_state_destroy") != NULL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, needed_libthr);
	ATF_TP_ADD_TC(tp, dlopen_now_resolves);
	return (atf_no_error());
}
