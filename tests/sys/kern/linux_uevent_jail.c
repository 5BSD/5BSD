/* SPDX-License-Identifier: BSD-2-Clause */
/* Native controller for Linux64 event isolation. Disposable BSD VMs only. */
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netlink/netlink.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int vjid, sjid;
static void cleanup(void)
{
 if(vjid>0) jail_remove(vjid);
 if(sjid>0) jail_remove(sjid);
 vjid=sjid=0;
}
static int makejail(int vnet)
{
 char name[64],error[256]={0}; int state=JAIL_SYS_NEW;
 snprintf(name,sizeof(name),"uevent-%d-%d",getpid(),vnet);
 struct iovec iov[]={
  {"name",5},{name,strlen(name)+1},{"path",5},{"/",2},
  {"persist",8},{NULL,0},{"errmsg",7},{error,sizeof(error)},
  {"vnet",5},{&state,sizeof(state)}
 };
 int jid=jail_set(iov,vnet?10:8,JAIL_CREATE);
 if(jid<0) fprintf(stderr,"uevent jail: %s\n",error);
 return jid;
}
static int command(int jid,const char *verb)
{
 pid_t p=fork(); int status;
 if(p<0) return 1;
 if(p==0) {
  if(jid && jail_attach(jid)<0) _exit(2);
  execl("/sbin/ifconfig","ifconfig","lo1",verb,(char*)NULL);
  _exit(3);
 }
 return waitpid(p,&status,0)!=p || !WIFEXITED(status) || WEXITSTATUS(status)!=0;
}
static int rename_interface(const char *from,const char *to)
{
 struct ifreq ifr={0}; int fd=socket(AF_INET,SOCK_DGRAM,0);
 if(fd<0) return 1;
 strlcpy(ifr.ifr_name,from,sizeof(ifr.ifr_name)); ifr.ifr_data=(char*)to;
 int rc=ioctl(fd,SIOCSIFNAME,&ifr); close(fd); return rc!=0;
}
static int scenario(int listener_jid,int actor_jid,int expect,int unpriv,int overflow)
{
 int ready[2],done[2],status,rc=0; char byte,options[64],expected[8];
 if(pipe(ready) || pipe(done)) return 1;
 pid_t p=fork();
 if(p<0) return 2;
 if(p==0) {
  close(ready[0]); close(done[1]); alarm(30);
  if(listener_jid && jail_attach(listener_jid)<0) _exit(3);
  snprintf(options,sizeof(options),"%d,%d,%d,%d",ready[1],done[0],unpriv,listener_jid==sjid?0:1);
  snprintf(expected,sizeof(expected),"%d",expect);
  execl("/tmp/kobject-uevent-linux","kobject-uevent-linux",overflow==1?"overflow":"observe",expected,options,(char*)NULL);
  _exit(4);
 }
 close(ready[1]); close(done[0]);
 if(read(ready[0],&byte,1)!=1 || byte!='R') rc=5;
 for(int n=0;n<(overflow==1?32:1) && !rc;n++) {
  if(command(actor_jid,"create")) rc=6;
  if(!rc && overflow==2) {
   const char *invalid[]={".","..","bad/name","bad:name","bad name"};
   for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]) && !rc;i++) {
    if(rename_interface("lo1",invalid[i])) rc=14;
    if(!rc && rename_interface(invalid[i],"lo1")) rc=15;
   }
  }
  if(!rc && command(actor_jid,"destroy")) rc=7;
 }
 if(write(done[1],"D",1)!=1 && !rc) rc=8;
 if(overflow==1 && !rc) {
  if(read(ready[0],&byte,1)!=1 || byte!='R') rc=10;
  if(!rc && command(actor_jid,"create")) rc=11;
  if(!rc && command(actor_jid,"destroy")) rc=12;
  if(write(done[1],"D",1)!=1 && !rc) rc=13;
 }
 close(ready[0]); close(done[1]);
 if(waitpid(p,&status,0)!=p || !WIFEXITED(status) || WEXITSTATUS(status)!=0) rc=9;
 return rc;
}
static int lifecycle(void)
{
 int fd=socket(AF_NETLINK,SOCK_DGRAM|SOCK_NONBLOCK,NETLINK_KOBJECT_UEVENT);
 struct sockaddr_nl addr={.nl_len=sizeof(addr),.nl_family=AF_NETLINK,.nl_groups=1};
 if(fd<0 || bind(fd,(void*)&addr,sizeof(addr))) return 1;
 if(command(0,"create") || command(0,"destroy")) return 2;
 pid_t p=fork(); int status;
 if(p<0) return 3;
 if(p==0) {
  close(fd);
  execl("/bin/sh","sh","-ec",
   "umount /sys; umount /proc; kldunload linsysfs; kldunload linprocfs; "
   "kldunload linux64; "
   "if kldstat -q -n linux_common.ko; then kldunload linux_common; fi; "
   "if kldstat -q -n linux_common.ko; then exit 1; fi; kldload linux64; "
   "mount -t linprocfs linprocfs /proc; mount -t linsysfs linsysfs /sys; "
   "ifconfig lo1 create; ifconfig lo1 destroy",(char*)NULL);
  _exit(4);
 }
 if(waitpid(p,&status,0)!=p || !WIFEXITED(status) || WEXITSTATUS(status)) return 5;
 unsigned count=0; unsigned long long previous=0;
 for (;;) {
  char packet[4096]; struct sockaddr_nl source; socklen_t len=sizeof(source);
  ssize_t n=recvfrom(fd,packet,sizeof(packet),0,(void*)&source,&len);
  if(n<0) { if(errno!=EAGAIN) return 6; break; }
  if(n==0 || packet[n-1]!=0 || len!=sizeof(source) || source.nl_pid!=0 || source.nl_groups!=1) return 7;
  const char *seq=NULL;
  for(char *item=packet;item<packet+n;item+=strlen(item)+1) {
   if(memchr(item,0,(size_t)(packet+n-item))==NULL) return 8;
   if(!strncmp(item,"SEQNUM=",7)) seq=item+7;
  }
  if(!seq) return 9;
  unsigned long long number=strtoull(seq,NULL,10);
  if(number<=previous) return 10;
  previous=number; if(++count>4) return 11;
 }
 close(fd); return count==4?0:12;
}
int main(void)
{
 signal(SIGPIPE,SIG_IGN); alarm(180); atexit(cleanup);
 vjid=makejail(1); sjid=makejail(0);
 if(vjid<0 || sjid<0) return 1;
 const char *names[]={"host_from_vnet","vnet_from_host","shared_from_host","same_vnet","same_host"};
 int listeners[]={0,vjid,sjid,vjid,0}, actors[]={vjid,0,0,vjid,0};
 int expected[]={0,0,0,2,2},failed=0;
 for(int uid=0;uid<2;uid++) for(int n=0;n<5;n++) {
  int rc=scenario(listeners[n],actors[n],expected[n],uid,0);
  printf("UEVENT_ISOLATION %s %s %d\n",names[n],uid?"unprivileged":"root",rc);
  fflush(stdout); if(rc) failed=1;
 }
 for(int uid=0;uid<2;uid++) {
  int rc=scenario(0,0,2,uid,1);
  printf("UEVENT_OVERFLOW %s %d\n",uid?"unprivileged":"root",rc);
  fflush(stdout); if(rc) failed=1;
 }
 for(int uid=0;uid<2;uid++) {
  int rc=scenario(0,0,12,uid,2);
  printf("UEVENT_NAMES %s %d\n",uid?"unprivileged":"root",rc);
  fflush(stdout); if(rc) failed=1;
 }
 cleanup();
 int rc=lifecycle();
 printf("UEVENT_LIFECYCLE %d\n",rc); if(rc) failed=1;
 return failed;
}
