/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdio.h>
#include "migration_credentials.h"
int main(void) {
    unsigned checks = 0;
    char text[66]; uint8_t output[32], expected[32];
    const char *hex = "0123456789abcdef";
    for (unsigned byte = 0; byte < 256; ++byte) {
        for (size_t i = 0; i < 32; ++i) {
            expected[i] = (byte + i) & 255;
            text[2*i] = hex[expected[i] >> 4];
            text[2*i+1] = hex[expected[i] & 15];
        }
        text[64] = 0;
        assert(migration_credentials_pin(text, output) == 0);
        assert(memcmp(output, expected, 32) == 0); ++checks;
        for (size_t i = 0; i < 64; ++i)
            if (text[i] >= 'a' && text[i] <= 'f') text[i] -= 'a' - 'A';
        assert(migration_credentials_pin(text, output) == 0);
        assert(memcmp(output, expected, 32) == 0); ++checks;
    }
    for (size_t position = 0; position < 64; ++position) {
        for (unsigned byte = 1; byte < 256; ++byte) {
            if ((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f') ||
                (byte >= 'A' && byte <= 'F')) continue;
            memset(text, '1', 64); text[64] = 0; text[position] = byte;
            memset(output, 0xa5, 32); memset(expected, 0xa5, 32);
            assert(migration_credentials_pin(text, output) == EINVAL);
            assert(memcmp(output, expected, 32) == 0); ++checks;
        }
    }
    memset(text, '1', 64); text[64] = 0;
    for (unsigned mask = 0; mask < 16; ++mask) {
        struct migration_tls_credentials output_config, before;
        memset(&output_config, 0xa5, sizeof(output_config)); before = output_config;
        bool enabled = false;
        int error = migration_credentials_config(mask & 1 ? "0" : NULL,
            mask & 2 ? "2147483647" : NULL, mask & 4 ? "42" : NULL,
            mask & 8 ? text : NULL, &output_config, &enabled);
        assert(enabled == (mask != 0));
        assert(error == ((mask == 0 || mask == 15) ? 0 : EINVAL));
        if (mask != 15) assert(memcmp(&before, &output_config, sizeof(before)) == 0);
        else assert(output_config.certificate_fd == 0 &&
            output_config.private_key_fd == INT_MAX && output_config.trust_fd == 42);
        ++checks;
    }
    memset(output, 0xa5, 32); memset(expected, 0xa5, 32);
    assert(migration_credentials_pin(NULL, output) == EINVAL);
    assert(migration_credentials_pin("short", output) == EINVAL);
    assert(migration_credentials_pin(text, NULL) == EINVAL);
    memset(text, '0', 64); text[64] = 0;
    assert(migration_credentials_pin(text, output) == EINVAL);
    assert(memcmp(output, expected, 32) == 0);
    struct migration_tls_credentials cfg; bool enabled = false;
    assert(migration_credentials_config(NULL,NULL,NULL,NULL,NULL,&enabled) == EINVAL);
    assert(migration_credentials_config(NULL,NULL,NULL,NULL,&cfg,NULL) == EINVAL);
    assert(migration_credentials_config("-1","1","2",text,&cfg,&enabled) == EINVAL);
    assert(enabled);
    assert(migration_credentials_config("0","1","2",text,&cfg,&enabled) == EINVAL);
    printf("PASS: %u credential encoding and partial-configuration properties\n", checks);
}
