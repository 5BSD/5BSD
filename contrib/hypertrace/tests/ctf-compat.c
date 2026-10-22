/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ctf_api.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
int main(int argc, char **argv)
{
    int err, fd;
    ctf_file_t *fp;
    ctf_id_t plain, copied;
    ctf_encoding_t enc = { 1, 0, 32 };
    CHECK(argc == 2);
#ifdef WRITE_CTF
    fp = ctf_create(&err);
    CHECK(fp != NULL);
    plain = ctf_add_integer(fp, CTF_ADD_ROOT, "plain", &enc);
    copied = ctf_add_integer_cp(fp, CTF_ADD_ROOT, "copied", &enc);
    CHECK(plain != CTF_ERR && copied != CTF_ERR);
    CHECK(ctf_type_copied(fp, plain) == 0);
    CHECK(ctf_type_copied(fp, copied) == 1);
    CHECK(ctf_update(fp) == 0);
    CHECK(ctf_type_copied(fp, copied) == 1);
    fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0 && ctf_write(fp, fd) == 0);
    CHECK(close(fd) == 0);
#else
    (void)fd; (void)enc;
    fp = ctf_open(argv[1], &err);
    CHECK(fp != NULL);
    plain = ctf_lookup_by_name(fp, "plain");
    copied = ctf_lookup_by_name(fp, "copied");
    CHECK(plain != CTF_ERR && copied != CTF_ERR);
    CHECK(ctf_type_size(fp, plain) == 4);
    CHECK(ctf_type_size(fp, copied) == 4);
#endif
    ctf_close(fp);
    return (0);
}
