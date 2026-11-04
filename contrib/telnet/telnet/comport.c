/* SPDX-License-Identifier: BSD-2-Clause */
#include <arpa/telnet.h>
#include <string.h>
#include "comport.h"

/* RFC 2217, section 2: client SET-BAUDRATE command. */
#define COMPORT_SET_BAUDRATE 1

size_t
telnet_comport_baudrate(uint32_t baudrate, unsigned char *output, size_t capacity)
{
    unsigned char frame[TELNET_COMPORT_BAUDRATE_MAX_FRAME];
    unsigned char value;
    size_t length = 0;
    int shift;

    frame[length++] = IAC;
    frame[length++] = SB;
    frame[length++] = TELOPT_COMPORT;
    frame[length++] = COMPORT_SET_BAUDRATE;
    for (shift = 24; shift >= 0; shift -= 8) {
        value = (unsigned char)(baudrate >> shift);
        frame[length++] = value;
        if (value == IAC)
            frame[length++] = IAC;
    }
    frame[length++] = IAC;
    frame[length++] = SE;
    if (length > capacity)
        return 0;
    memcpy(output, frame, length);
    return length;
}
