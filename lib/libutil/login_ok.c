/*-
 * Copyright (c) 1996 by
 * David Nugent <davidn@blaze.net.au>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. This work was done expressly for inclusion into FreeBSD.  Other use
 *    is permitted provided this notation is included.
 * 4. Absolutely no warranty of function or purpose is made by the authors.
 * 5. Modifications may be freely made to this file providing the above
 *    conditions are met.
 *
 * Support allow/deny lists in login class capabilities
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <errno.h>
#include <fnmatch.h>
#include <login_cap.h>
#include <stdlib.h>
#include <string.h>
#include <ttyent.h>
#include <unistd.h>


/* -- support functions -- */

/*
 * login_strinlist()
 * This function is intentionally public - reused by TAS.
 * Returns TRUE (non-zero) if a string matches a pattern
 * in a given array of patterns. 'flags' is passed directly
 * to fnmatch(3).
 */

int
login_strinlist(const char **list, char const *str, int flags)
{
    int rc = 0;

    if (str != NULL && *str != '\0') {
	int	i = 0;

	while (rc == 0 && list[i] != NULL)
	    rc = fnmatch(list[i++], str, flags) == 0;
    }
    return rc;
}


/*
 * login_str2inlist()
 * Locate either or two strings in a given list
 */

int
login_str2inlist(const char **ttlst, const char *str1, const char *str2, int flags)
{
    int	    rc = 0;

    if (login_strinlist(ttlst, str1, flags))
	rc = 1;
    else if (login_strinlist(ttlst, str2, flags))
	rc = 1;
    return rc;
}


/*
 * login_timelist()
 * This function is intentionally public - reused by TAS.
 * Returns an allocated list of time periods given an array
 * of time periods in ascii form.
 */

login_time_t *
login_timelist(login_cap_t *lc, char const *cap, int *ltno,
	       login_time_t **ltptr)
{
    int			j = 0;
    struct login_time	*lt = NULL;
    const char		**tl;

    /* Distinguish an absent capability from a failed allocation. */
    errno = 0;
    if ((tl = login_getcaplist(lc, cap, NULL)) != NULL) {

	while (tl[j] != NULL) {
	    if (j == LC_MAXTIMES) {
		errno = EINVAL;
		return (NULL);
	    }
	    j++;
	}
	j++; /* Include the terminator. */
	if (*ltno >= j)
	    lt = *ltptr;
	else if ((lt = realloc(*ltptr, j * sizeof(struct login_time))) != NULL) {
	    *ltno = j;
	    *ltptr = lt;
	}
	if (lt != NULL) {
	    int i, n = 0;
	    login_time_t parsed;

	    for (i = 0; i < j - 1; i++) {
		parsed = parse_lt(tl[i]);
		if (errno != 0)
		    return (NULL);
		/* None/Never are empty periods, not list terminators. */
		if (parsed.lt_dow != LTM_NONE)
		    lt[n++] = parsed;
	    }
	    lt[n].lt_dow = LTM_NONE;
	}
    }
    return lt;
}


/*
 * login_ttyok()
 * This function is a variation of auth_ttyok(), but it checks two
 * arbitrary capability lists not necessarily related to access.
 * This hook is provided for the accounted/exclude accounting lists.
 */

int
login_ttyok(login_cap_t *lc, const char *tty, const char *allowcap,
	    const char *denycap)
{
    int	    rc = 1;

    if (lc != NULL && tty != NULL && *tty != '\0') {
	struct ttyent	*te;
	char		*grp;
	const char	**ttl;

	te = getttynam(tty);  /* Need group name */
	grp = te ? te->ty_group : NULL;
	errno = 0;
	ttl = login_getcaplist(lc, allowcap, NULL);

	if ((ttl == NULL && errno != 0) ||
	    (ttl != NULL && !login_str2inlist(ttl, tty, grp, 0)))
	    rc = 0;	/* tty or ttygroup not in allow list */
	else {

	    errno = 0;
	    ttl = login_getcaplist(lc, denycap, NULL);
	    if ((ttl == NULL && errno != 0) ||
		(ttl != NULL && login_str2inlist(ttl, tty, grp, 0)))
		rc = 0; /* tty or ttygroup in deny list */
	}
    }

    return rc;
}


/*
 * auth_ttyok()
 * Determine whether or not login on a tty is accessible for
 * a login class
 */

int
auth_ttyok(login_cap_t *lc, const char * tty)
{
    return login_ttyok(lc, tty, "ttys.allow", "ttys.deny");
}


/*
 * login_hostok()
 * This function is a variation of auth_hostok(), but it checks two
 * arbitrary capability lists not necessarily related to access.
 * This hook is provided for the accounted/exclude accounting lists.
 */

int
login_hostok(login_cap_t *lc, const char *host, const char *ip,
	     const char *allowcap, const char *denycap)
{
    int	    rc = 1; /* Default is ok */

    if (lc != NULL &&
	((host != NULL && *host != '\0') || (ip != NULL && *ip != '\0'))) {
	const char **hl;

	errno = 0;
	hl = login_getcaplist(lc, allowcap, NULL);
	if ((hl == NULL && errno != 0) ||
	    (hl != NULL && !login_str2inlist(hl, host, ip, FNM_CASEFOLD)))
	    rc = 0;	/* host or IP not in allow list */
	else {

	    errno = 0;
	    hl = login_getcaplist(lc, denycap, NULL);
	    if ((hl == NULL && errno != 0) ||
		(hl != NULL && login_str2inlist(hl, host, ip, FNM_CASEFOLD)))
		rc = 0; /* host or IP in deny list */
	}
    }

    return rc;
}


/*
 * auth_hostok()
 * Determine whether or not login from a host is ok
 */

int
auth_hostok(login_cap_t *lc, const char *host, const char *ip)
{
    return login_hostok(lc, host, ip, "host.allow", "host.deny");
}


/*
 * auth_timeok()
 * Determine whether or not login is ok at a given time
 */

int
auth_timeok(login_cap_t *lc, time_t t)
{
    int	    rc = 1; /* Default is ok */

    if (lc != NULL) {
	struct tm	converted, *tptr;

	int 	ltimesno = 0;
	struct login_time *ltimes = NULL;

	/* time(3) failure must not disable account restrictions. */
	if (t == (time_t)-1)
	    return 0;
	if ((tptr = localtime_r(&t, &converted)) != NULL) {
	    struct login_time	*lt;

	  lt = login_timelist(lc, "times.allow", &ltimesno, &ltimes);
	  if ((lt == NULL && errno != 0) ||
	      (lt != NULL && in_ltms(lt, tptr, NULL) == -1))
	      rc = 0;	  /* not in allowed times list */
	  else {

	      lt = login_timelist(lc, "times.deny", &ltimesno, &ltimes);
	      if ((lt == NULL && errno != 0) ||
		  (lt != NULL && in_ltms(lt, tptr, NULL) != -1))
		  rc = 0; /* in deny times list */
	  }
	  if (ltimes) {
	      free(ltimes);
	      ltimes = NULL;
	      ltimesno = 0;
	  }
	} else
	    rc = 0; /* cannot evaluate the supplied time */
    }

    return rc;
}
