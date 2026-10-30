/* SPDX-License-Identifier: BSD-2-Clause */
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); return 1; } } while (0)
int main(int argc, char **argv)
{
    static const unsigned char expected[16] = {
        0xa4,0x48,0x01,0x7a,0xaf,0x21,0xd8,0x52,
        0x5f,0xc1,0x0a,0xe8,0x7a,0xa6,0x72,0x9d };
    char path[PATH_MAX];
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *provider;
    EVP_MD *md;
    CHECK(argc == 6 && ctx != NULL);
    CHECK(realpath(argv[1], path) != NULL);
    provider = OSSL_PROVIDER_load(ctx, path);
    CHECK(provider != NULL);
    md = EVP_MD_fetch(ctx, "MD4", "provider=legacy");
    CHECK(md != NULL);
    CHECK(EVP_Digest("abc", 3, output, &size, md, NULL));
    CHECK(size == sizeof(expected) && memcmp(output, expected, size) == 0);
    EVP_MD_free(md);
    CHECK(OSSL_PROVIDER_unload(provider));
    OSSL_LIB_CTX_free(ctx);
    /* Loading and the dynamic-engine ABI are tested here. Hardware-specific
     * initialization and acceleration require suitable devices/CPUs. */
    for (int i = 2; i < argc; i++) {
        void *module;
        CHECK(realpath(argv[i], path) != NULL);
        module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (module == NULL) fprintf(stderr, "%s\n", dlerror());
        CHECK(module != NULL);
        CHECK(dlsym(module, "bind_engine") != NULL);
        CHECK(dlsym(module, "v_check") != NULL);
        CHECK(dlclose(module) == 0);
    }
    puts("legacy MD4 known answer and four engine loading checks passed");
    return 0;
}
