/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 kernel-origin uevents. Disposable guests only. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct nladdr { uint16_t family,pad; uint32_t pid,groups; };
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"UEVENT line %d: %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while (0)
static pid_t actor=-1;
static int actor_command=-1;
static void stop_actor(void)
{
 if(actor_command>=0) { close(actor_command); actor_command=-1; }
 if(actor>0) { int status; while(waitpid(actor,&status,0)<0 && errno==EINTR) {} actor=-1; }
}
static const char *field(const char *packet,size_t size,const char *key)
{
 size_t offset=0,len=strlen(key);
 while(offset<size) {
  const char *end=memchr(packet+offset,0,size-offset); CHECK(end!=NULL);
  if ((size_t)(end-packet-offset)>len && !memcmp(packet+offset,key,len) && packet[offset+len]=='=') return packet+offset+len+1;
  offset=(size_t)(end-packet)+1;
 }
 return NULL;
}
static int listener_scoped(int type,uint32_t group,uint32_t expected_group)
{
 int fd=socket(AF_NETLINK,type|SOCK_NONBLOCK|SOCK_CLOEXEC,15); CHECK(fd>=0);
 struct nladdr addr={.family=AF_NETLINK,.groups=group};
 CHECK(bind(fd,(void*)&addr,sizeof(addr))==0);
 socklen_t len=sizeof(addr); CHECK(getsockname(fd,(void*)&addr,&len)==0 && len==sizeof(addr) && addr.pid!=0 && addr.groups==expected_group);
 return fd;
}
static int listener(int type,uint32_t group)
{
 return listener_scoped(type,group,group);
}
static unsigned drain_datagrams(int fd,int short_read)
{
 unsigned count=0;
 for (;;) {
  ssize_t size=recv(fd,NULL,0,MSG_PEEK|MSG_TRUNC);
  if(size<0) { CHECK(errno==EAGAIN); return count; }
  CHECK(size>8 && count++<1024);
  if(short_read) {
   char small[8]; struct iovec iov={small,sizeof(small)};
   struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
   CHECK(recvmsg(fd,&msg,0)==sizeof(small) && (msg.msg_flags&MSG_TRUNC));
  } else CHECK(recv(fd,NULL,0,MSG_TRUNC)==size);
 }
}
static void recv_flags(void)
{
 int pair[2]; char data[8]={0};
 CHECK(socketpair(AF_UNIX,SOCK_DGRAM,0,pair)==0);
 CHECK(send(pair[0],data,sizeof(data),0)==sizeof(data));
 struct iovec iov={data,2};
 struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
 CHECK(recvmsg(pair[1],&msg,MSG_PEEK|MSG_DONTWAIT)==2);
 CHECK(msg.msg_flags==MSG_TRUNC);
 iov.iov_len=sizeof(data); msg.msg_flags=0;
 CHECK(recvmsg(pair[1],&msg,MSG_CMSG_CLOEXEC)==sizeof(data));
 CHECK(msg.msg_flags==MSG_CMSG_CLOEXEC);
 CHECK(close(pair[0])==0 && close(pair[1])==0);
}
static int observe(const char *expected,const char *options)
{
 int ready,done,unpriv,groups; char c,packet[4096]; unsigned count=0;
 CHECK(sscanf(options,"%d,%d,%d,%d",&ready,&done,&unpriv,&groups)==4);
 if(unpriv) { CHECK(setgroups(0,NULL)==0); CHECK(setgid(65534)==0 && setuid(65534)==0); }
 int fd=listener_scoped(SOCK_DGRAM,1,(uint32_t)groups);
 CHECK(write(ready,"R",1)==1); CHECK(read(done,&c,1)==1 && c=='D');
 for (;;) {
  ssize_t len=recv(fd,packet,sizeof(packet),0);
  if(len<0) { CHECK(errno==EAGAIN); break; }
  CHECK(len>0 && count++<1024);
  const char *name=field(packet,(size_t)len,"INTERFACE");
  CHECK(name && !strcmp(name,"lo1"));
 }
 CHECK(count==(unsigned)atoi(expected));
 CHECK(close(fd)==0 && close(ready)==0 && close(done)==0);
 return 0;
}
static int overflow_observe(const char *options)
{
 int ready,done,unpriv,groups,limit=1024; char c;
 CHECK(sscanf(options,"%d,%d,%d,%d",&ready,&done,&unpriv,&groups)==4);
 if(unpriv) { CHECK(setgroups(0,NULL)==0); CHECK(setgid(65534)==0 && setuid(65534)==0); }
 int fd=listener(SOCK_DGRAM,1);
 CHECK(setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&limit,sizeof(limit))==0);
 CHECK(write(ready,"R",1)==1 && read(done,&c,1)==1 && c=='D');
 CHECK(recv(fd,&c,1,0)==-1 && errno==ENOBUFS);
 /* A single interface operation may also emit queue-device events on Linux. */
 limit=65536;
 CHECK(setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&limit,sizeof(limit))==0);
 unsigned drained=0,attempts=0;
 for (;;) {
  char packet[4096]; CHECK(attempts++<4096);
  ssize_t n=recv(fd,packet,sizeof(packet),0);
  if(n>0) { drained++; continue; }
  CHECK(n<0);
  if(errno==ENOBUFS) continue;
  CHECK(errno==EAGAIN);
  struct pollfd waitfd={.fd=fd,.events=POLLIN};
  int ready_count=poll(&waitfd,1,100); CHECK(ready_count>=0);
  if(ready_count==0) break;
 }
 CHECK(drained>0);
 CHECK(write(ready,"R",1)==1 && read(done,&c,1)==1 && c=='D');
 CHECK(drain_datagrams(fd,0)>=2);
 CHECK(close(fd)==0 && close(ready)==0 && close(done)==0);
 return 0;
}
int main(int argc,char **argv)
{
 int command[2],reply[2],fd,quiet,type,enabled=1,status;
 CHECK(argc==4); alarm(60);
 if(!strcmp(argv[1],"observe")) return observe(argv[2],argv[3]);
 if(!strcmp(argv[1],"overflow")) return overflow_observe(argv[3]);
 type=!strcmp(argv[1],"raw") ? SOCK_RAW : SOCK_DGRAM;
 recv_flags();
 CHECK(pipe(command)==0 && pipe(reply)==0);
 pid_t child=fork(); CHECK(child>=0);
 if (!child) {
  const char **cmd; int owned=0;
  signal(SIGPIPE,SIG_IGN);
  static const char *linux_cmd[]={"/sbin/ip link add lo1 type dummy","/sbin/ip link set lo1 name uevt1","/sbin/ip link del uevt1"};
  static const char *bsd_cmd[]={"/sbin/ifconfig lo1 create","/sbin/ifconfig lo1 name uevt1","/sbin/ifconfig uevt1 destroy"};
  cmd=!strcmp(argv[3],"linux") ? linux_cmd : bsd_cmd;
  close(command[1]); close(reply[0]);
  for (int i=0;i<3;i++) {
   char c; if (read(command[0],&c,1)!=1) break;
   int result=system(cmd[i]); if(i==0 && result==0) owned=1;
   if(write(reply[1],&result,sizeof(result))!=sizeof(result)) break;
   if(result!=0) break;
  }
  if (owned && !strcmp(argv[3],"linux")) {
   (void)system("/sbin/ip link del lo1 2>/dev/null; /sbin/ip link del uevt1 2>/dev/null");
  } else if (owned) {
   (void)system("/sbin/ifconfig lo1 destroy 2>/dev/null; /sbin/ifconfig uevt1 destroy 2>/dev/null");
  }
  _exit(0);
 }
 close(command[0]); close(reply[1]);
 actor=child; actor_command=command[1]; CHECK(atexit(stop_actor)==0);
 if (!strcmp(argv[2],"unprivileged")) { CHECK(setgroups(0,NULL)==0); CHECK(setgid(65534)==0 && setuid(65534)==0); }
 fd=listener(type,1); quiet=listener(type,0);
 int shortfd=listener(type,1), zerofd=listener(type,1), subfd=listener(type,0);
 int group=1;
 CHECK(setsockopt(subfd,270,1,&group,sizeof(group))==0);
 CHECK(setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled))==0);
 socklen_t optlen=sizeof(enabled); enabled=0;
 CHECK(getsockopt(fd,SOL_SOCKET,SO_PASSCRED,&enabled,&optlen)==0 && enabled==1);
 unsigned long long lastseq=0;
 const char *actions[]={"add","move","remove"};
 for (int step=0;step<3;step++) {
  char packet[4096],control[CMSG_SPACE(sizeof(struct ucred))],path[4096],expected[4096];
  struct nladdr src;
  if(step==2) { enabled=0; CHECK(setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled))==0); }
  CHECK(write(command[1],"x",1)==1);
  CHECK(read(reply[0],&status,sizeof(status))==sizeof(status) && status==0);
  int found=0;
  for(int attempt=0;attempt<128 && !found;attempt++) {
   struct pollfd pollfd={.fd=fd,.events=POLLIN}; CHECK(poll(&pollfd,1,5000)==1 && (pollfd.revents&POLLIN));
   ssize_t size=recv(fd,NULL,0,MSG_PEEK|MSG_TRUNC); CHECK(size>0 && size<=(ssize_t)sizeof(packet));
   char shortbuf[8]; struct iovec shortiov={shortbuf,sizeof(shortbuf)};
   struct msghdr peek={.msg_name=&src,.msg_namelen=sizeof(src),.msg_iov=&shortiov,.msg_iovlen=1};
   CHECK(recvmsg(fd,&peek,MSG_PEEK)==sizeof(shortbuf) && (peek.msg_flags&MSG_TRUNC));
   CHECK(!!(peek.msg_flags&MSG_CTRUNC)==(step!=2));
   if(step!=2) {
    struct iovec fulliov={packet,sizeof(packet)};
    struct msghdr tiny={.msg_iov=&fulliov,.msg_iovlen=1,.msg_control=control,.msg_controllen=1};
    CHECK(recvmsg(fd,&tiny,MSG_PEEK)==size && (tiny.msg_flags&MSG_CTRUNC) && tiny.msg_controllen==0);
    tiny.msg_controllen=CMSG_LEN(sizeof(int)); tiny.msg_flags=0;
    CHECK(recvmsg(fd,&tiny,MSG_PEEK)==size && (tiny.msg_flags&MSG_CTRUNC) && tiny.msg_controllen==CMSG_LEN(sizeof(int)));
    struct cmsghdr *partial=CMSG_FIRSTHDR(&tiny);
    CHECK(partial && partial->cmsg_len==CMSG_LEN(sizeof(int)) && partial->cmsg_type==SCM_CREDENTIALS && partial->cmsg_level==SOL_SOCKET);
    int pid; memcpy(&pid,CMSG_DATA(partial),sizeof(pid)); CHECK(pid==0);
    tiny.msg_controllen=CMSG_LEN(sizeof(struct ucred)); tiny.msg_flags=0;
    CHECK(recvmsg(fd,&tiny,MSG_PEEK)==size && !(tiny.msg_flags&MSG_CTRUNC) && tiny.msg_controllen==CMSG_LEN(sizeof(struct ucred)));
   }
   struct iovec iov={packet,sizeof(packet)};
   struct msghdr msg={.msg_name=&src,.msg_namelen=sizeof(src),.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
   CHECK(recvmsg(fd,&msg,0)==size && !(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)));
   CHECK(src.family==AF_NETLINK && src.pid==0 && src.groups==1);
   CHECK(packet[size-1]==0);
   struct cmsghdr *cmsg=CMSG_FIRSTHDR(&msg);
   if(step!=2) {
    CHECK(cmsg && cmsg->cmsg_level==SOL_SOCKET && cmsg->cmsg_type==SCM_CREDENTIALS && cmsg->cmsg_len==CMSG_LEN(sizeof(struct ucred)));
    struct ucred cred; memcpy(&cred,CMSG_DATA(cmsg),sizeof(cred)); CHECK(cred.pid==0 && cred.uid==0 && cred.gid==0);
   } else CHECK(cmsg==NULL);
   const char *interface=field(packet,(size_t)size,"INTERFACE"), *subsystem=field(packet,(size_t)size,"SUBSYSTEM");
   if (!interface || !subsystem || strcmp(subsystem,"net") || strcmp(interface,step==0 ? "lo1" : "uevt1")) continue;
   const char *action=field(packet,(size_t)size,"ACTION"), *devpath=field(packet,(size_t)size,"DEVPATH"), *seq=field(packet,(size_t)size,"SEQNUM"), *index=field(packet,(size_t)size,"IFINDEX");
   CHECK(action && devpath && seq && index && !strcmp(action,actions[step]) && atoi(index)>0);
   CHECK(snprintf(expected,sizeof(expected),"%s@%s",action,devpath)>0 && !strcmp(packet,expected));
   unsigned long long sequence=strtoull(seq,NULL,10); CHECK(sequence>lastseq); lastseq=sequence;
   if(step==1) { const char *old=field(packet,(size_t)size,"DEVPATH_OLD"); CHECK(old && strstr(old,"/net/lo1")); }
   CHECK(snprintf(path,sizeof(path),"/sys%s",devpath)>0);
   struct stat st;
   if(step!=2) {
    CHECK(stat(path,&st)==0 && S_ISDIR(st.st_mode));
    char classpath[512],link[512],attribute[512],text[256]; struct stat classst;
    CHECK(snprintf(classpath,sizeof(classpath),"/sys/class/net/%s",interface)>0);
    ssize_t n=readlink(classpath,link,sizeof(link)-1); CHECK(n>0); link[n]=0;
    CHECK(snprintf(expected,sizeof(expected),"../../devices/virtual/net/%s",interface)>0 && !strcmp(link,expected));
    CHECK(stat(classpath,&classst)==0 && classst.st_ino==st.st_ino && classst.st_dev==st.st_dev);
    CHECK(snprintf(attribute,sizeof(attribute),"%s/subsystem",path)>0);
    CHECK(realpath(attribute,link)!=NULL && !strcmp(link,"/sys/class/net"));
    CHECK(snprintf(attribute,sizeof(attribute),"%s/uevent",path)>0);
    int attribute_fd=open(attribute,O_RDONLY); CHECK(attribute_fd>=0);
    n=read(attribute_fd,text,sizeof(text)-1); CHECK(n>0); text[n]=0; CHECK(close(attribute_fd)==0);
    CHECK(snprintf(expected,sizeof(expected),"INTERFACE=%s\n",interface)>0 && strstr(text,expected));
    CHECK(snprintf(expected,sizeof(expected),"IFINDEX=%s\n",index)>0 && strstr(text,expected));
   } else CHECK(stat(path,&st)==-1 && errno==ENOENT);
   printf("UEVENT_PACKET %s %s %s %s\n",action,devpath,index,seq); found=1;
  }
  CHECK(found);
  CHECK(drain_datagrams(shortfd,1)>0);
  CHECK(drain_datagrams(zerofd,0)>0);
  unsigned subscribed=drain_datagrams(subfd,0);
  CHECK(step==1 ? subscribed==0 : subscribed>0);
  if(step==0) CHECK(setsockopt(subfd,270,2,&group,sizeof(group))==0);
  if(step==1) CHECK(setsockopt(subfd,270,1,&group,sizeof(group))==0);
  char c; CHECK(recv(quiet,&c,1,0)==-1 && errno==EAGAIN);
 }
 CHECK(close(command[1])==0 && close(reply[0])==0); actor_command=-1;
 CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0); actor=-1;
 CHECK(close(fd)==0 && close(quiet)==0 && close(shortfd)==0 && close(zerofd)==0 && close(subfd)==0);
 printf("UEVENT_PASS %s %s\n",argv[1],argv[2]); return 0;
}
