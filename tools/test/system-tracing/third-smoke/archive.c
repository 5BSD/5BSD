/* SPDX-License-Identifier: BSD-2-Clause */
#include <archive.h>
#include <archive_entry.h>
#include <assert.h>
#include <string.h>
int main(void) {
 char buf[16384], data[8]; size_t used=0;
 struct archive *a=archive_write_new(); struct archive_entry *e=archive_entry_new();
 assert(archive_write_set_format_ustar(a)==ARCHIVE_OK);
 assert(archive_write_open_memory(a,buf,sizeof(buf),&used)==ARCHIVE_OK);
 archive_entry_set_pathname(e,"test"); archive_entry_set_size(e,4);
 archive_entry_set_filetype(e,AE_IFREG); archive_entry_set_perm(e,0600);
 assert(archive_write_header(a,e)==ARCHIVE_OK);
 assert(archive_write_data(a,"data",4)==4);
 assert(archive_write_finish_entry(a)==ARCHIVE_OK);
 assert(archive_write_close(a)==ARCHIVE_OK); archive_write_free(a); archive_entry_free(e);
 a=archive_read_new(); archive_read_support_format_all(a);
 assert(archive_read_open_memory(a,buf,used)==ARCHIVE_OK);
 assert(archive_read_next_header(a,&e)==ARCHIVE_OK);
 assert(archive_read_data(a,data,sizeof(data))==4); assert(!memcmp(data,"data",4));
 assert(archive_read_next_header(a,&e)==ARCHIVE_EOF);
 assert(archive_read_close(a)==ARCHIVE_OK); archive_read_free(a);
 a=archive_read_new(); archive_read_support_format_all(a);
 assert(archive_read_open_memory(a,"invalid",7)!=ARCHIVE_OK); archive_read_free(a);
 return 0;
}
