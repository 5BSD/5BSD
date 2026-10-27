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
 * Login period parsing and comparison functions.
 */

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <login_cap.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static struct
{
    const char	*dw;
    u_char       cn;
    u_char       fl;
} dws[] =
{
    { "su", 2, LTM_SUN }, { "mo", 2, LTM_MON }, { "tu", 2, LTM_TUE },
    { "we", 2, LTM_WED }, { "th", 2, LTM_THU }, { "fr", 2, LTM_FRI },
    { "sa", 2, LTM_SAT }, { "any",3, LTM_ANY }, { "all",3, LTM_ANY },
    { "wk", 2, LTM_WK  }, { "wd", 2, LTM_WD  }, { NULL, 0, 0       }
};

static const char *
parse_time(const char *ptr, u_short *t)
{
    unsigned int val = 0, digits = 0;

    while (isdigit((unsigned char)*ptr)) {
	if (++digits > 4)
	    return (NULL);
	val = val * 10 + (*ptr++ - '0');
    }
    if (digits == 0 || val > 2400 || val % 100 >= 60)
	return (NULL);
    *t = (u_short)((val / 100) * 60 + val % 100);
    return (ptr);
}


login_time_t
parse_lt(const char *str)
{
    login_time_t t = {0}, m = {0};
    const char *p = str;
    int i;

    errno = 0;
    if (str == NULL || *str == '\0')
	goto invalid;
    if (strcasecmp(str, "Never") == 0 || strcasecmp(str, "None") == 0)
	return (t);

    while (isalpha((unsigned char)*p)) {
	for (i = 0; dws[i].dw != NULL; i++)
	    if (strncasecmp(p, dws[i].dw, dws[i].cn) == 0)
		break;
	if (dws[i].dw == NULL)
	    goto invalid;
	m.lt_dow |= dws[i].fl;
	p += dws[i].cn;
    }
    if (m.lt_dow == LTM_NONE)
	m.lt_dow = LTM_ANY;
    m.lt_end = 1440;
    if (isdigit((unsigned char)*p)) {
	p = parse_time(p, &m.lt_start);
	if (p == NULL)
	    goto invalid;
    }
    if (*p == '-') {
	p = parse_time(p + 1, &m.lt_end);
	if (p == NULL)
	    goto invalid;
    }
    if (*p != '\0' || m.lt_start > m.lt_end)
	goto invalid;
    return (m);

invalid:
    errno = EINVAL;
    return (t);
}


int
in_ltm(const login_time_t *ltm, struct tm *tt, time_t *ends)
{
    int	    rc = 0;

    if (tt != NULL) {
	/* First, examine the day of the week */
	if ((u_char)(0x01 << tt->tm_wday) & ltm->lt_dow) {
	    /* Convert `current' time to minute of the day */
	    u_short	now = (u_short)((tt->tm_hour * 60) + tt->tm_min);

	    if (tt->tm_sec > 30)
		++now;
	    if (now >= ltm->lt_start && now < ltm->lt_end) {
		rc = 2;
		if (ends != NULL) {
		    /* If requested, return ending time for this period */
		    tt->tm_hour = (int)(ltm->lt_end / 60);
		    tt->tm_min  = (int)(ltm->lt_end % 60);
		    *ends = mktime(tt);
		}
	    }
	}
    }
    return (rc);
}


int
in_lt(const login_time_t *ltm, time_t *t)
{

    return (in_ltm(ltm, localtime(t), t));
}

int
in_ltms(const login_time_t *ltm, struct tm *tm, time_t *t)
{
    int	    i = 0;

    while (i < LC_MAXTIMES && ltm[i].lt_dow != LTM_NONE) {
	if (in_ltm(ltm + i, tm, t))
	    return (i);
	i++;
    }
    return (-1);
}

int
in_lts(const login_time_t *ltm, time_t *t)
{

    return (in_ltms(ltm, localtime(t), t));
}
