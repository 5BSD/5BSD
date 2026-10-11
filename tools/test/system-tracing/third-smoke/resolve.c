/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <pwd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
int main(int argc, char **argv) {
 struct addrinfo *ai=NULL; struct __res_state state; unsigned char q[12]={0},a[64];
 memset(&state,0,sizeof(state)); errno=0;
 assert(res_nsend(&state,q,sizeof(q),a,sizeof(a))==-1); assert(errno==ESRCH);
 if (argc==2) {
  assert(res_ninit(&state)==0); state.nscount=1; state.retry=1; state.retrans=1;
  state.nsaddr_list[0].sin_family=AF_INET;
  state.nsaddr_list[0].sin_port=htons(atoi(argv[1]));
  state.nsaddr_list[0].sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  state.options &= ~RES_USEVC;
  assert(res_nsend(&state,q,sizeof(q),a,sizeof(a))==12);
  res_nclose(&state);
 }
 assert(getaddrinfo("localhost",NULL,NULL,&ai)==0); freeaddrinfo(ai);
 assert(getpwuid(getuid())!=NULL); return 0;
}
