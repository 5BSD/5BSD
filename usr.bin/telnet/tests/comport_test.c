/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdio.h>
#include <string.h>
#include "comport.h"

int
main(void)
{
    static const struct {
        uint32_t rate;
        size_t length;
        unsigned char wire[TELNET_COMPORT_BAUDRATE_MAX_FRAME];
    } cases[] = {
        {9600, 10, {255,250,44,1,0,0,37,128,255,240}},
        {0, 10, {255,250,44,1,0,0,0,0,255,240}},
        {255, 11, {255,250,44,1,0,0,0,255,255,255,240}},
        {65535, 12, {255,250,44,1,0,0,255,255,255,255,255,240}},
        {UINT32_MAX, 14, {255,250,44,1,255,255,255,255,255,255,255,255,255,240}},
    };
    unsigned char output[TELNET_COMPORT_BAUDRATE_MAX_FRAME + 2], untouched[sizeof(output)];
    size_t i, capacity, length;

    memset(untouched, 0xa5, sizeof(untouched));
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for (capacity = 0; capacity < cases[i].length; capacity++) {
            memcpy(output, untouched, sizeof(output));
            if (telnet_comport_baudrate(cases[i].rate, output + 1, capacity) != 0 ||
                memcmp(output, untouched, sizeof(output)) != 0)
                return 1;
        }
        memcpy(output, untouched, sizeof(output));
        length = telnet_comport_baudrate(cases[i].rate, output + 1, cases[i].length);
        if (length != cases[i].length || memcmp(output + 1, cases[i].wire, length) != 0 ||
            output[0] != 0xa5 || memcmp(output + 1 + length, untouched, sizeof(output) - 1 - length) != 0)
            return 1;
    }
    puts("RFC 2217 baud frames and capacity guards pass");
    return 0;
}
