/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>
#include <lib9p.h>

/* 9P2000 Tversion: size=19, type=100, NOTAG, msize=8192, "9P2000". */
static const unsigned char wire[] = {
    19, 0, 0, 0, 100, 255, 255, 0, 32, 0, 0, 6, 0,
    '9', 'P', '2', '0', '0', '0'
};

static struct l9p_message
message(void *buffer, size_t size, size_t split, enum l9p_pack_mode mode)
{
    struct l9p_message m = { .lm_mode = mode, .lm_niov = 2 };
    m.lm_iov[0] = (struct iovec){ buffer, split };
    m.lm_iov[1] = (struct iovec){ (char *)buffer + split, size - split };
    return m;
}

int
main(void)
{
    unsigned char buffer[sizeof(wire)];
    for (size_t split = 1; split < sizeof(wire); split++) {
        union l9p_fcall call = {0};
        call.hdr.type = L9P_TVERSION;
        call.hdr.tag = 0xffff;
        call.version.msize = 8192;
        call.version.version = "9P2000";
        memset(buffer, 0xa5, sizeof(buffer));
        struct l9p_message m = message(buffer, sizeof(buffer), split, L9P_PACK);
        if (l9p_pufcall(&m, &call, L9P_2000) != 0 ||
            memcmp(buffer, wire, sizeof(wire)) != 0) {
            fprintf(stderr, "encode failed at iovec split %zu\n", split);
            return 1;
        }
        memset(&call, 0, sizeof(call));
        m = message(buffer, sizeof(buffer), split, L9P_UNPACK);
        int result = l9p_pufcall(&m, &call, L9P_2000);
        int valid = result == 0 && call.hdr.type == L9P_TVERSION &&
            call.hdr.tag == 0xffff && call.version.msize == 8192 &&
            call.version.version != NULL && strcmp(call.version.version, "9P2000") == 0;
        l9p_freefcall(&call);
        if (!valid) return 2;
    }
    for (size_t length = 0; length < sizeof(wire); length++) {
        union l9p_fcall call = {0};
        memcpy(buffer, wire, sizeof(wire));
        struct l9p_message m = message(buffer, length, length / 2, L9P_UNPACK);
        int result = l9p_pufcall(&m, &call, L9P_2000);
        l9p_freefcall(&call);
        if (result == 0) {
            fprintf(stderr, "accepted truncated packet of %zu bytes\n", length);
            return 3;
        }
    }
    union l9p_fcall call = {0};
    memcpy(buffer, wire, sizeof(wire));
    buffer[15] = 0;
    struct l9p_message m = message(buffer, sizeof(buffer), 14, L9P_UNPACK);
    int result = l9p_pufcall(&m, &call, L9P_2000);
    l9p_freefcall(&call);
    return result == 0 ? 4 : 0;
}
