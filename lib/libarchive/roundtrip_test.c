/* SPDX-License-Identifier: BSD-2-Clause */
#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)
static int exercise(int filter, int encrypted)
{
    unsigned char *buffer = malloc(1024 * 1024), data[65536], decoded[65536];
    size_t used = 0;
    struct archive *writer = archive_write_new(), *reader;
    struct archive_entry *entry = archive_entry_new(), *got;
    CHECK(buffer && writer && entry);
    for (size_t i = 0; i < sizeof(data); i++) data[i] = (unsigned char)(i * 31 + i / 17);
    if (encrypted) {
        CHECK(archive_write_set_format_zip(writer) == ARCHIVE_OK);
        CHECK(archive_write_set_options(writer, "zip:encryption=aes256") == ARCHIVE_OK);
        CHECK(archive_write_set_passphrase(writer, "test passphrase") == ARCHIVE_OK);
    } else CHECK(archive_write_set_format_pax_restricted(writer) == ARCHIVE_OK);
    CHECK(archive_write_add_filter(writer, filter) == ARCHIVE_OK);
    CHECK(archive_write_open_memory(writer, buffer, 1024 * 1024, &used) == ARCHIVE_OK);
    archive_entry_set_pathname(entry, "dir/payload");
    archive_entry_set_filetype(entry, AE_IFREG); archive_entry_set_perm(entry, 0640);
    archive_entry_set_size(entry, sizeof(data));
    CHECK(archive_write_header(writer, entry) == ARCHIVE_OK);
    CHECK(archive_write_data(writer, data, sizeof(data)) == sizeof(data));
    CHECK(archive_write_close(writer) == ARCHIVE_OK);
    CHECK(archive_write_free(writer) == ARCHIVE_OK); archive_entry_free(entry);
    reader = archive_read_new(); CHECK(reader);
    CHECK(archive_read_support_filter_all(reader) == ARCHIVE_OK);
    CHECK(archive_read_support_format_all(reader) == ARCHIVE_OK);
    if (encrypted) CHECK(archive_read_add_passphrase(reader, "test passphrase") == ARCHIVE_OK);
    CHECK(archive_read_open_memory(reader, buffer, used) == ARCHIVE_OK);
    CHECK(archive_read_next_header(reader, &got) == ARCHIVE_OK);
    CHECK(strcmp(archive_entry_pathname(got), "dir/payload") == 0);
    CHECK(archive_entry_size(got) == sizeof(data) && archive_entry_perm(got) == 0640);
    CHECK(archive_read_data(reader, decoded, sizeof(decoded)) == sizeof(decoded));
    CHECK(memcmp(data, decoded, sizeof(data)) == 0);
    CHECK(archive_read_next_header(reader, &got) == ARCHIVE_EOF);
    CHECK(archive_read_free(reader) == ARCHIVE_OK);
    if (encrypted) {
        reader = archive_read_new(); CHECK(reader);
        CHECK(archive_read_support_format_zip(reader) == ARCHIVE_OK);
        CHECK(archive_read_add_passphrase(reader, "wrong passphrase") == ARCHIVE_OK);
        CHECK(archive_read_open_memory(reader, buffer, used) == ARCHIVE_OK);
        CHECK(archive_read_next_header(reader, &got) == ARCHIVE_OK);
        CHECK(archive_read_data(reader, decoded, sizeof(decoded)) < 0);
        archive_read_free(reader);
    }
    free(buffer);
    return 0;
}
int main(void)
{
    int filters[] = {ARCHIVE_FILTER_NONE, ARCHIVE_FILTER_GZIP, ARCHIVE_FILTER_BZIP2,
        ARCHIVE_FILTER_XZ, ARCHIVE_FILTER_ZSTD};
    for (size_t i = 0; i < sizeof(filters) / sizeof(filters[0]); i++) CHECK(exercise(filters[i], 0) == 0);
    CHECK(exercise(ARCHIVE_FILTER_NONE, 1) == 0);
    puts("five filter roundtrips, metadata, encrypted ZIP and wrong-password rejection passed");
    return 0;
}
