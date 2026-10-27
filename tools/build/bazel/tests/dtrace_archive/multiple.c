/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/sdt.h>
int multiple_selected(int value)
{
    DTRACE_PROBE1(archiveprobe, used, value);
    return value + 1;
}
int multiple_unselected(int value)
{
    DTRACE_PROBE1(archiveprobe, unused, value);
    return value + 2;
}
