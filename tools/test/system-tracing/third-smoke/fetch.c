/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <stdio.h>
#include <fetch.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
 char url[256],buf[8]; FILE *f; assert(argc==3); fetchTimeout=2;
 snprintf(url,sizeof(url),"http://127.0.0.1:%s/ok",argv[1]);
 f=fetchGetURL(url,""); assert(f); assert(fread(buf,1,4,f)==4); assert(!memcmp(buf,"data",4)); fclose(f);
 snprintf(url,sizeof(url),"http://127.0.0.1:%s/missing",argv[1]); assert(fetchGetURL(url,"")==NULL);
 snprintf(url,sizeof(url),"http://127.0.0.1:%s/",argv[2]); assert(fetchGetURL(url,"")==NULL);
 snprintf(url,sizeof(url),"https://127.0.0.1:%s/",argv[1]); assert(fetchGetURL(url,"")==NULL);
 return 0;
}
