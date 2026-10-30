/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/ctf_api.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>
int main(void)
{
    int error = 0;
    char path[] = "ctf-roundtrip.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) err(1, "mkstemp");
    ctf_file_t *fp = ctf_create(&error);
    if (!fp) errx(1, "create: %s", ctf_errmsg(error));
    ctf_encoding_t encoding = {CTF_INT_SIGNED, 0, 32};
    ctf_id_t integer = ctf_add_integer(fp, CTF_ADD_ROOT, "fixture_integer", &encoding);
    ctf_id_t record = ctf_add_struct(fp, CTF_ADD_ROOT, "fixture_record");
    /* Commit type definitions before member sizing queries resolve them. */
    if (integer == CTF_ERR || record == CTF_ERR || ctf_update(fp) != 0 ||
        ctf_add_member(fp, record, "value", integer) != 0 || ctf_update(fp) != 0 ||
        ctf_write(fp, fd) != 0) errx(1, "create/write: %s", ctf_errmsg(ctf_errno(fp)));
    ctf_close(fp);
    if (close(fd)) err(1, "close");
    fp = ctf_open(path, &error);
    if (!fp) errx(1, "reopen: %s", ctf_errmsg(error));
    record = ctf_lookup_by_name(fp, "struct fixture_record");
    ctf_membinfo_t member;
    if (record == CTF_ERR || ctf_type_size(fp, record) != 4 ||
        ctf_member_info(fp, record, "value", &member) != 0 || member.ctm_offset != 0 ||
        ctf_type_encoding(fp, member.ctm_type, &encoding) != 0 ||
        encoding.cte_bits != 32 || encoding.cte_format != CTF_INT_SIGNED)
        errx(1, "reopened type/member mismatch");
    ctf_close(fp);
    if (unlink(path)) err(1, "unlink");
    return (0);
}
