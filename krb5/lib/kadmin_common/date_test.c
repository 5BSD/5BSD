/* SPDX-License-Identifier: BSD-2-Clause */
#include <time.h>
#include "kadmin.h"

int main(void)
{
    time_t start = 946684800; /* 2000-01-01 00:00:00 UTC */
    char absolute[] = "2000-01-01 00:00:00 UTC";
    char future[] = "tomorrow";
    char past[] = "1 day ago";
    char invalid[] = "not a date";
    if (get_date_rel(absolute, start) != start)
        return 1;
    if (get_date_rel(future, start) != start + 86400)
        return 2;
    if (get_date_rel(past, start) != start - 86400)
        return 3;
    if (get_date_rel(invalid, start) != (time_t)-1)
        return 4;
    return 0;
}
