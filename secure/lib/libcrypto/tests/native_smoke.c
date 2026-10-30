/* SPDX-License-Identifier: BSD-2-Clause */
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", __FILE__, __LINE__, #x); ERR_print_errors_fp(stderr); return 1; } } while (0)
int main(void)
{
    static const unsigned char sha256_abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    /* NIST AES-128-GCM: zero key, IV and one zero plaintext block. */
    static const unsigned char ciphertext[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78 };
    static const unsigned char expected_tag[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf };
    unsigned char hash[32], key[16] = {0}, iv[12] = {0}, plain[16] = {0};
    unsigned char encrypted[32], decoded[32], tag[16], random[32], signature[128];
    unsigned int len = 0;
    int n = 0, final = 0;
    size_t siglen = sizeof(signature);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    BIGNUM *a = BN_new(), *e = BN_new(), *mod = BN_new(), *r = BN_new();
    BN_CTX *bnctx = BN_CTX_new();
    CHECK(c && m && pkey && a && e && mod && r && bnctx);
    CHECK(EVP_Digest("abc", 3, hash, &len, EVP_sha256(), NULL));
    CHECK(len == sizeof(hash) && memcmp(hash, sha256_abc, sizeof(hash)) == 0);
    CHECK(EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, key, iv));
    CHECK(EVP_EncryptUpdate(c, encrypted, &n, plain, sizeof(plain)) && n == 16);
    CHECK(EVP_EncryptFinal_ex(c, encrypted + n, &final) && final == 0);
    CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag));
    CHECK(memcmp(encrypted, ciphertext, 16) == 0 && memcmp(tag, expected_tag, 16) == 0);
    CHECK(EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), NULL, key, iv));
    CHECK(EVP_DecryptUpdate(c, decoded, &n, encrypted, 16));
    CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag));
    CHECK(EVP_DecryptFinal_ex(c, decoded + n, &final));
    CHECK(memcmp(decoded, plain, 16) == 0);
    tag[0] ^= 1;
    CHECK(EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), NULL, key, iv));
    CHECK(EVP_DecryptUpdate(c, decoded, &n, encrypted, 16));
    CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag));
    CHECK(EVP_DecryptFinal_ex(c, decoded + n, &final) <= 0);
    CHECK(RAND_bytes(random, sizeof(random)) == 1);
    CHECK(BN_set_word(a, 2) && BN_set_word(e, 20) && BN_set_word(mod, 17));
    CHECK(BN_mod_exp(r, a, e, mod, bnctx) && BN_is_word(r, 16));
    CHECK(EVP_DigestSignInit(m, NULL, NULL, NULL, pkey));
    CHECK(EVP_DigestSign(m, signature, &siglen, (const unsigned char *)"message", 7));
    CHECK(EVP_DigestVerifyInit(m, NULL, NULL, NULL, pkey));
    CHECK(EVP_DigestVerify(m, signature, siglen, (const unsigned char *)"message", 7) == 1);
    signature[0] ^= 1;
    CHECK(EVP_DigestVerify(m, signature, siglen, (const unsigned char *)"message", 7) == 0);
    EVP_CIPHER_CTX_free(c); EVP_MD_CTX_free(m); EVP_PKEY_free(pkey);
    BN_free(a); BN_free(e); BN_free(mod); BN_free(r); BN_CTX_free(bnctx);
    puts("OpenSSL digest, AEAD, rejection, random, bignum and signature checks passed");
    return 0;
}
