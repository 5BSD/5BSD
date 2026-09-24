/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 UNIX SOCK_DIAG ABI probe; disposable guests only. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "UNIX_DIAG line %d: %s errno=%d\n", __LINE__, #x, errno); exit(1); } } while (0)
struct nladdr { uint16_t family, pad; uint32_t pid, groups; };
struct nlhead { uint32_t len; uint16_t type, flags; uint32_t seq, pid; };
struct request { uint8_t family, protocol; uint16_t pad; uint32_t states, ino, show, cookie[2]; };
struct reply { uint8_t family, type, state, pad; uint32_t ino, cookie[2]; };
struct attr { uint16_t len, type; };
struct record { struct reply msg; unsigned attrs, namelen, nicons; char name[108]; uint32_t peer, uid, queues[2], memory[9], vfs[2], icons[16]; uint8_t shutdown; };
_Static_assert(sizeof(struct request) == 24, "request size");
_Static_assert(sizeof(struct reply) == 16, "reply size");
static struct record found;
static unsigned matches, sequence;

static int
query(struct request req, int dump, uint32_t target, int shorten)
{
 struct { struct nlhead h; struct request r; } packet = {0};
 struct nladdr addr = {.family=16};
 struct timeval timeout = {.tv_sec=5};
 int fd=socket(16, SOCK_RAW, 4), done=0, result=0;
 CHECK(fd>=0); CHECK(bind(fd, (void *)&addr, sizeof(addr))==0);
 CHECK(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0);
 packet.h.len=sizeof(packet)-shorten; packet.h.type=20;
 packet.h.flags=1|(dump?0x300:0); packet.h.seq=++sequence; packet.r=req;
 CHECK(sendto(fd,&packet,packet.h.len,0,(void *)&addr,sizeof(addr))==packet.h.len);
 matches=0; memset(&found,0,sizeof(found));
 while (!done) {
  char buf[65536]; socklen_t alen=sizeof(addr);
  ssize_t n=recvfrom(fd,buf,sizeof(buf),0,(void *)&addr,&alen);
  CHECK(n>=(ssize_t)sizeof(struct nlhead)); CHECK(addr.pid==0);
  for (size_t off=0;off<(size_t)n;) {
   struct nlhead h; CHECK((size_t)n-off>=sizeof(h)); memcpy(&h,buf+off,sizeof(h));
   CHECK(h.len>=sizeof(h)&&h.len<=(size_t)n-off); CHECK(h.seq==sequence);
   if (h.type==2||h.type==3) {
    CHECK(h.len>=sizeof(h)+sizeof(int)); memcpy(&result,buf+off+sizeof(h),sizeof(int)); done=1;
   } else {
    struct record r={0}; CHECK(h.type==20&&h.len>=sizeof(h)+sizeof(r.msg));
    memcpy(&r.msg,buf+off+sizeof(h),sizeof(r.msg)); CHECK(r.msg.family==1);
    CHECK(!dump||(h.flags&2));
    for (size_t a=sizeof(h)+sizeof(r.msg);a<h.len;) {
     struct attr at; CHECK(h.len-a>=sizeof(at)); memcpy(&at,buf+off+a,sizeof(at));
     CHECK(at.len>=sizeof(at)&&at.len<=h.len-a); size_t size=at.len-sizeof(at);
     const void *data=buf+off+a+sizeof(at); CHECK(at.type<32); r.attrs|=1U<<at.type;
     switch (at.type) {
     case 0: CHECK(size<=sizeof(r.name));memcpy(r.name,data,size);r.namelen=size;break;
     case 1: CHECK(size==sizeof(r.vfs));memcpy(r.vfs,data,size);break;
     case 2: CHECK(size==sizeof(r.peer));memcpy(&r.peer,data,size);break;
     case 3: CHECK(size%4==0);r.nicons=size/4;memcpy(r.icons,data,size<sizeof(r.icons)?size:sizeof(r.icons));break;
     case 4: CHECK(size==sizeof(r.queues));memcpy(r.queues,data,size);break;
     case 5: CHECK(size>=sizeof(r.memory));memcpy(r.memory,data,sizeof(r.memory));break;
     case 6: CHECK(size==1);memcpy(&r.shutdown,data,1);break;
     case 7: CHECK(size==sizeof(r.uid));memcpy(&r.uid,data,size);break;
     }
     a+=(at.len+3)&~3U; CHECK(a<=h.len);
    }
    CHECK(r.attrs&(1U<<6));
    if (r.msg.ino==target) {found=r;matches++;}
    if (!dump) done=1;
   }
   off+=(h.len+3)&~3U; CHECK(off<=(size_t)n);
  }
 }
 CHECK(close(fd)==0);return result;
}
static uint32_t inode(int fd) {struct stat st;CHECK(fstat(fd,&st)==0);return st.st_ino;}

int
main(int argc,char **argv)
{
 CHECK(argc==3);alarm(120);
 const char *uidtext=getenv("DIAG_UID");
 if (uidtext) {uid_t uid=strtoul(uidtext,NULL,10);CHECK(setgid(uid)==0);CHECK(setuid(uid)==0);}
 if (!strcmp(argv[1],"hold")) {
  int fd=socket(AF_UNIX,SOCK_DGRAM,0);CHECK(fd>=0);
  FILE *out=fopen(argv[2],"w");CHECK(out);CHECK(fprintf(out,"%u\n",inode(fd))>0);CHECK(fclose(out)==0);
  sleep(300);CHECK(close(fd)==0);return 0;
 }
 int type=atoi(argv[1]); const char *mode=argv[2];
 CHECK(type==SOCK_STREAM||type==SOCK_DGRAM||type==SOCK_SEQPACKET);
 int pair[2]; struct sockaddr_un name={.sun_family=AF_UNIX}; size_t namelen=0;
 if (!strcmp(mode,"pair")) {CHECK(socketpair(AF_UNIX,type,0,pair)==0);}
 else {
  pair[0]=socket(AF_UNIX,type,0);CHECK(pair[0]>=0);pair[1]=-1;
  if (!strcmp(mode,"abstract")) {
   int n=snprintf(name.sun_path+1,sizeof(name.sun_path)-1,"diag-%u-%u",(unsigned)getuid(),(unsigned)getpid());
   CHECK(n>0);name.sun_path[n+2]='x';namelen=n+3;
  } else {
   CHECK(!strcmp(mode,"path"));
   int n=snprintf(name.sun_path,sizeof(name.sun_path),"/tmp/diag-%u-%u",(unsigned)getuid(),(unsigned)getpid());
   CHECK(n>0);namelen=n+1;unlink(name.sun_path);
  }
  CHECK(bind(pair[0],(void *)&name,offsetof(struct sockaddr_un,sun_path)+namelen)==0);
  if (type!=SOCK_DGRAM) CHECK(listen(pair[0],8)==0);
 }
 uint32_t ino=inode(pair[0]);
 struct request req={.family=1,.states=~0U,.show=1|2|4|8|16|32|64,.cookie={~0U,~0U}};
 CHECK(query(req,1,ino,0)==0);CHECK(matches==1);
 CHECK(found.msg.type==type);CHECK(found.uid==getuid());CHECK(found.attrs&(1U<<7));
 CHECK(found.attrs&(1U<<4));CHECK(found.attrs&(1U<<5));
 unsigned state=pair[1]>=0?1:type==SOCK_DGRAM?7:10; CHECK(found.msg.state==state);
 if (namelen) {CHECK(found.namelen==namelen);CHECK(memcmp(found.name,name.sun_path,namelen)==0);}
 if (namelen&&name.sun_path[0]) {
  struct stat st;CHECK(stat(name.sun_path,&st)==0);CHECK(found.attrs&(1U<<1));
  CHECK(found.vfs[0]==(uint32_t)st.st_ino);CHECK(found.vfs[1]==(uint32_t)((major(st.st_dev)<<20)|minor(st.st_dev)));
 } else CHECK(!(found.attrs&(1U<<1)));
 if (pair[1]>=0) {CHECK(found.peer==inode(pair[1]));CHECK(found.memory[1]>0);}
 if (getenv("DIAG_CHURN") && strcmp(getenv("DIAG_CHURN"),"0")) {
  pid_t child=fork();CHECK(child>=0);
  if (child==0) {
   close(pair[0]);if (pair[1]>=0) close(pair[1]);
   for (unsigned j=0;j<1000;j++) {int fds[2];CHECK(socketpair(AF_UNIX,type,0,fds)==0);CHECK(close(fds[0])==0);CHECK(close(fds[1])==0);}
   _exit(0);
  }
  for (unsigned j=0;j<20;j++) {CHECK(query(req,1,ino,0)==0);CHECK(matches==1);}
  int status;CHECK(waitpid(child,&status,0)==child);CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
  puts("UNIX_DIAG_CHURN_PASS");
 }
 req.ino=ino;memcpy(req.cookie,found.msg.cookie,sizeof(req.cookie));
 if (pair[1]<0 && type!=SOCK_DGRAM) {
  int clients[3], accepted[3];uint32_t ids[3];
  for (unsigned j=0;j<3;j++) {
   clients[j]=socket(AF_UNIX,type,0);CHECK(clients[j]>=0);
   CHECK(connect(clients[j],(void *)&name,offsetof(struct sockaddr_un,sun_path)+namelen)==0);
   ids[j]=inode(clients[j]);
  }
  CHECK(query(req,0,ino,0)==0);CHECK(found.nicons==3);CHECK(found.queues[0]==3);
  for (unsigned j=0;j<3;j++) {unsigned seen=0;for (unsigned k=0;k<3;k++) seen+=found.icons[k]==ids[j];CHECK(seen==1);}
  struct request client_req=req;client_req.ino=ids[0];client_req.cookie[0]=client_req.cookie[1]=~0U;
  CHECK(query(client_req,0,ids[0],0)==0);CHECK(found.attrs&(1U<<2));CHECK(found.peer==0);
  for (unsigned j=0;j<3;j++) {accepted[j]=accept(pair[0],NULL,NULL);CHECK(accepted[j]>=0);}
  CHECK(query(req,0,ino,0)==0);CHECK(found.attrs&(1U<<3));CHECK(found.nicons==0);CHECK(found.queues[0]==0);
  CHECK(query(client_req,0,ids[0],0)==0);CHECK(found.peer==inode(accepted[0]));
  for (unsigned j=0;j<3;j++) {CHECK(close(accepted[j])==0);CHECK(close(clients[j])==0);}
 }

 CHECK(query(req,0,ino,0)==0);CHECK(matches==1);CHECK(found.uid==getuid());
 req.cookie[0]^=0x40000000;CHECK(query(req,0,ino,0)==-ESTALE);req.cookie[0]^=0x40000000;
 req.states=0;CHECK(query(req,1,ino,0)==0);CHECK(matches==0);req.states=~0U;
 CHECK(query(req,1,ino,1)==-EINVAL);
 if (pair[1]>=0) {
  CHECK(write(pair[1],"hello",5)==5);CHECK(query(req,0,ino,0)==0);CHECK(found.queues[0]>=5);
  char bytes[8];CHECK(read(pair[0],bytes,sizeof(bytes))==5);
  CHECK(shutdown(pair[0],SHUT_WR)==0);CHECK(query(req,0,ino,0)==0);CHECK(found.shutdown&2);
  CHECK(close(pair[1])==0);
 }
 CHECK(close(pair[0])==0);CHECK(query(req,0,ino,0)==-ENOENT);
 if (namelen&&name.sun_path[0]) CHECK(unlink(name.sun_path)==0);
 const char *hidden=getenv("DIAG_HIDE_INO"), *visible=getenv("DIAG_SHOW_INO");
 if (hidden) {CHECK(query(req,1,strtoul(hidden,NULL,10),0)==0);CHECK(matches==0);}
 if (visible) {CHECK(query(req,1,strtoul(visible,NULL,10),0)==0);CHECK(matches==1);}
 printf("UNIX_DIAG_PASS %d %s\n",type,mode);return 0;
}
