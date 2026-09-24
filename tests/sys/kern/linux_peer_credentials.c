/* SPDX-License-Identifier: BSD-2-Clause */
/* Run only in disposable Linux or Linuxulator guests, initially as root. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef SO_PEERGROUPS
#define SO_PEERGROUPS 59
#endif
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr, \
 "PEER_FAIL line=%d errno=%d\n", __LINE__, errno); exit(1); } } while (0)
static void absent(int fd)
{
 struct ucred c; gid_t g[32]; int p; socklen_t n;
 n=sizeof(g); errno=0;
 CHECK(getsockopt(fd,SOL_SOCKET,SO_PEERGROUPS,g,&n)==-1 && errno==ENODATA);
 n=sizeof(p); errno=0;
 CHECK(getsockopt(fd,SOL_SOCKET,SO_PEERPIDFD,&p,&n)==-1 && errno==ENODATA);
 memset(&c,0xaa,sizeof(c));n=sizeof(c);
 CHECK(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&c,&n)==0);
 CHECK(n==sizeof(c) && c.pid==0 && c.uid==(uid_t)-1 && c.gid==(gid_t)-1);
}
static void pair(int type, int count)
{
 int s[2],i,p; gid_t groups[32],want[15];
 struct ucred c; unsigned char buf[64]; socklen_t n;
 for(i=0;i<15;i++) want[i]=17+12*i;
 printf("PEER_PAIR type=%d groups=%d\n",type,count);
 CHECK(setgroups(count,want)==0);
 CHECK(socketpair(AF_UNIX,type,0,s)==0);
 /* The snapshot belongs to connection creation, not the querying process. */
 CHECK(setgroups(0,NULL)==0);
 memset(groups,0xaa,sizeof(groups));n=sizeof(groups);
 CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERGROUPS,groups,&n)==0);
 CHECK(n==(socklen_t)count*sizeof(gid_t));
 for(i=0;i<count;i++) CHECK(groups[i]==want[i]);
 CHECK(groups[count]==(gid_t)0xaaaaaaaa);
 n=count ? count*sizeof(gid_t)-1 : 0;errno=0;
 i=getsockopt(s[0],SOL_SOCKET,SO_PEERGROUPS,buf,&n);
 CHECK(count ? i==-1 && errno==ERANGE : i==0);
 CHECK(n==(socklen_t)count*sizeof(gid_t));
 n=(socklen_t)-1;errno=0;
 CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERGROUPS,buf,&n)==-1 && errno==EINVAL);
 errno=0;CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERGROUPS,buf,(void *)1)==-1 && errno==EFAULT);
 if(count){n=sizeof(groups);errno=0;CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERGROUPS,(void *)1,&n)==-1 && errno==EFAULT);}
 n=sizeof(c); CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERCRED,&c,&n)==0);
 CHECK(c.pid==getpid() && c.uid==geteuid() && c.gid==getegid());
 for(i=0;i<=(int)sizeof(c)+1;i++){
  memset(buf,0xaa,sizeof(buf));n=i;
  CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERCRED,buf,&n)==0);
  CHECK(n==(socklen_t)(i<(int)sizeof(c)?i:(int)sizeof(c)));
  CHECK(!memcmp(buf,&c,n) && buf[n]==0xaa);
 }
 n=sizeof(p);CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERPIDFD,&p,&n)==0);
 CHECK(n==sizeof(p) && p>=0);close(p);
 n=sizeof(p);errno=0;CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERPIDFD,(void *)1,&n)==-1 && errno==EFAULT);
 /* Security labels are optional, but must honor the caller's capacity. */
 n=sizeof(buf);errno=0;i=getsockopt(s[0],SOL_SOCKET,SO_PEERSEC,buf,&n);
 if(i==0){
  socklen_t required=n;CHECK(required>0 && required<=sizeof(buf));
  memset(buf,0xaa,sizeof(buf));n=required-1;errno=0;
  CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERSEC,buf,&n)==-1 && errno==ERANGE);
  CHECK(n==required && buf[0]==0xaa);
  n=(socklen_t)-1;errno=0;
  CHECK(getsockopt(s[0],SOL_SOCKET,SO_PEERSEC,buf,&n)==-1 && errno==EINVAL);
 } else CHECK(errno==ENOPROTOOPT || errno==EOPNOTSUPP);
 close(s[0]);close(s[1]);
}
int main(void)
{
 int f,i,j;int families[]={AF_INET,AF_INET6,AF_UNIX};int types[]={SOCK_STREAM,SOCK_DGRAM};
 for(i=0;i<3;i++)for(j=0;j<2;j++){
  f=socket(families[i],types[j],0);CHECK(f>=0);absent(f);close(f);
 }
 for(i=0;i<2;i++){pair(types[i],0);pair(types[i],3);pair(types[i],15);}
 printf("PEER_CREDENTIALS_PASS checks=%u\n",checks);return 0;
}
