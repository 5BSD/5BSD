/* SPDX-License-Identifier: BSD-2-Clause */
/* Anonymous-pipe open-description tests. Disposable guests only. */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { \
 fprintf(stderr, "PIPE_REOPEN line %d: %s errno=%d\n", __LINE__, #x, errno); \
 exit(1); } } while (0)
static int reopen(int fd, int flags)
{
 char name[64];
 snprintf(name, sizeof(name), "/proc/self/fd/%d", fd);
 return open(name, flags);
}
static void same_inode(int a, int b)
{
 struct stat x,y;
 CHECK(fstat(a,&x)==0 && fstat(b,&y)==0);
 CHECK(S_ISFIFO(x.st_mode) && x.st_dev==y.st_dev && x.st_ino==y.st_ino);
 CHECK((x.st_mode & 0777)==0600 && x.st_uid==getuid());
}
int main(int argc, char **argv)
{
 int p[2], n=-1, other=-1; char c;
 CHECK(argc >= 2); alarm(30); signal(SIGPIPE,SIG_IGN);
 if (argc>2 && !strcmp(argv[2],"unprivileged")) {
  CHECK(setgid(65534)==0); CHECK(setuid(65534)==0);
 }
 CHECK(pipe2(p,O_NONBLOCK|O_CLOEXEC)==0);
 if (!strcmp(argv[1],"identity")) {
  same_inode(p[0],p[1]);
 } else if (!strcmp(argv[1],"matrix")) {
  for (int end=0;end<2;end++) for (int access=0;access<3;access++) {
   n=reopen(p[end],access|O_NONBLOCK); CHECK(n>=0);
   same_inode(p[0],n);
   CHECK((fcntl(n,F_GETFL)&O_ACCMODE)==access);
   if (access==O_RDONLY) CHECK(write(n,"x",1)==-1 && errno==EBADF);
   else CHECK(write(n,"x",1)==1);
   if (access==O_WRONLY) CHECK(read(n,&c,1)==-1 && errno==EBADF);
   else {
    if (access==O_RDONLY) CHECK(write(p[1],"x",1)==1);
    CHECK(read(n,&c,1)==1 && c=='x');
   }
   if (access==O_WRONLY) CHECK(read(p[0],&c,1)==1 && c=='x');
   CHECK(close(n)==0); n=-1;
  }
 } else if (!strcmp(argv[1],"flags")) {
  n=reopen(p[0],O_RDONLY); CHECK(n>=0);
  CHECK((fcntl(n,F_GETFL)&O_NONBLOCK)==0);
  CHECK(fcntl(n,F_GETFD)==0);
  CHECK((fcntl(p[0],F_GETFL)&O_NONBLOCK)!=0);
  CHECK(fcntl(n,F_SETFL,O_NONBLOCK)==0);
  CHECK(fcntl(p[0],F_SETFL,0)==0);
  CHECK((fcntl(n,F_GETFL)&O_NONBLOCK)!=0);
  other=dup(n); CHECK(other>=0);
  CHECK(fcntl(other,F_SETFL,0)==0);
  CHECK((fcntl(n,F_GETFL)&O_NONBLOCK)==0);
 } else if (!strcmp(argv[1],"reader_lifetime")) {
  n=reopen(p[1],O_RDONLY|O_NONBLOCK); CHECK(n>=0);
  CHECK(close(p[0])==0); p[0]=-1;
  CHECK(write(p[1],"r",1)==1); CHECK(read(n,&c,1)==1 && c=='r');
  CHECK(close(n)==0); n=-1;
  CHECK(write(p[1],"x",1)==-1 && errno==EPIPE);
 } else if (!strcmp(argv[1],"writer_lifetime")) {
  n=reopen(p[0],O_WRONLY|O_NONBLOCK); CHECK(n>=0);
  CHECK(close(p[1])==0); p[1]=-1;
  CHECK(read(p[0],&c,1)==-1 && errno==EAGAIN);
  CHECK(write(n,"w",1)==1); CHECK(read(p[0],&c,1)==1 && c=='w');
  CHECK(close(n)==0); n=-1;
  CHECK(read(p[0],&c,1)==0);
 } else if (!strcmp(argv[1],"rdwr")) {
  n=reopen(p[0],O_RDWR|O_NONBLOCK); CHECK(n>=0);
  CHECK(close(p[0])==0 && close(p[1])==0); p[0]=p[1]=-1;
  CHECK(write(n,"d",1)==1); CHECK(read(n,&c,1)==1 && c=='d');
  CHECK(read(n,&c,1)==-1 && errno==EAGAIN);
  struct pollfd pollfd={.fd=n,.events=POLLIN|POLLOUT};
  CHECK(poll(&pollfd,1,0)==1 && pollfd.revents==POLLOUT);
 } else if (!strcmp(argv[1],"no_readers")) {
  CHECK(close(p[0])==0); p[0]=-1;
  n=reopen(p[1],O_WRONLY); CHECK(n>=0);
  CHECK(write(n,"x",1)==-1 && errno==EPIPE);
  other=reopen(n,O_RDONLY|O_NONBLOCK); CHECK(other>=0);
  CHECK(write(n,"q",1)==1 && read(other,&c,1)==1 && c=='q');
 } else if (!strcmp(argv[1],"no_writers")) {
  CHECK(close(p[1])==0); p[1]=-1;
  n=reopen(p[0],O_RDONLY); CHECK(n>=0);
  struct pollfd pollfd={.fd=n,.events=POLLIN};
  CHECK(poll(&pollfd,1,0)==1 && (pollfd.revents&POLLHUP)!=0);
  CHECK(read(n,&c,1)==0);
  other=reopen(n,O_WRONLY|O_NONBLOCK); CHECK(other>=0);
  CHECK(write(other,"q",1)==1 && read(n,&c,1)==1 && c=='q');
 } else if (!strcmp(argv[1],"opath")) {
  n=reopen(p[0],O_PATH|O_CLOEXEC); CHECK(n>=0);
  same_inode(p[0],n);
  CHECK(close(p[0])==0 && close(p[1])==0); p[0]=p[1]=-1;
  CHECK(read(n,&c,1)==-1 && errno==EBADF);
  CHECK(write(n,"x",1)==-1 && errno==EBADF);
  other=reopen(n,O_RDWR|O_NONBLOCK); CHECK(other>=0);
  CHECK(write(other,"p",1)==1 && read(other,&c,1)==1 && c=='p');
 } else if (!strcmp(argv[1],"opath_queue")) {
  n=reopen(p[0],O_PATH); CHECK(n>=0);
  CHECK(write(p[1],"old",3)==3);
  CHECK(close(p[0])==0 && close(p[1])==0); p[0]=p[1]=-1;
  other=reopen(n,O_RDWR|O_NONBLOCK); CHECK(other>=0);
  CHECK(read(other,&c,1)==-1 && errno==EAGAIN);
  CHECK(write(other,"n",1)==1 && read(other,&c,1)==1 && c=='n');
 } else if (!strcmp(argv[1],"cloexec")) {
  n=reopen(p[0],O_RDONLY|O_NONBLOCK|O_CLOEXEC); CHECK(n>=0);
  CHECK(fcntl(n,F_GETFD)==FD_CLOEXEC);
 } else if (!strcmp(argv[1],"directory")) {
  CHECK(reopen(p[0],O_RDONLY|O_DIRECTORY)==-1 && errno==ENOTDIR);
 } else if (!strcmp(argv[1],"queue")) {
  n=reopen(p[1],O_RDONLY|O_NONBLOCK); CHECK(n>=0);
  CHECK(write(p[1],"abc",3)==3);
  int count; struct stat st;
  CHECK(fstat(n,&st)==0 && st.st_size==0 && st.st_blocks==0);
  CHECK(ioctl(n,FIONREAD,&count)==0 && count==3);
  CHECK(ioctl(p[1],FIONREAD,&count)==0 && count==3);
  CHECK(read(n,&c,1)==1 && c=='a');
  CHECK(read(p[0],&c,1)==1 && c=='b');
  CHECK(ioctl(n,FIONREAD,&count)==0 && count==1);
  CHECK(read(n,&c,1)==1 && c=='c');
 } else if (!strcmp(argv[1],"epoll")) {
  int ep=epoll_create1(EPOLL_CLOEXEC); CHECK(ep>=0);
  n=reopen(p[0],O_RDONLY|O_NONBLOCK); CHECK(n>=0);
  struct epoll_event ev={.events=EPOLLIN,.data.u64=42}, out;
  CHECK(epoll_ctl(ep,EPOLL_CTL_ADD,n,&ev)==0);
  CHECK(epoll_wait(ep,&out,1,0)==0);
  CHECK(write(p[1],"e",1)==1);
  CHECK(epoll_wait(ep,&out,1,0)==1 && out.events==EPOLLIN && out.data.u64==42);
  CHECK(close(p[1])==0); p[1]=-1;
  CHECK(epoll_wait(ep,&out,1,0)==1 && out.events==(EPOLLIN|EPOLLHUP));
  CHECK(read(n,&c,1)==1 && c=='e');
  CHECK(epoll_wait(ep,&out,1,0)==1 && out.events==EPOLLHUP);
  other=reopen(n,O_WRONLY|O_NONBLOCK); CHECK(other>=0);
  CHECK(epoll_wait(ep,&out,1,0)==0);
  CHECK(close(ep)==0);
 } else if (!strcmp(argv[1],"epoll_writer")) {
  int ep=epoll_create1(EPOLL_CLOEXEC); CHECK(ep>=0);
  n=reopen(p[1],O_WRONLY|O_NONBLOCK); CHECK(n>=0);
  struct epoll_event ev={.events=EPOLLOUT,.data.u64=43}, out;
  CHECK(epoll_ctl(ep,EPOLL_CTL_ADD,n,&ev)==0);
  CHECK(epoll_wait(ep,&out,1,0)==1 && out.events==EPOLLOUT);
  CHECK(close(p[0])==0); p[0]=-1;
  CHECK(epoll_wait(ep,&out,1,0)==1 && out.events==(EPOLLOUT|EPOLLERR));
  other=reopen(n,O_RDONLY|O_NONBLOCK); CHECK(other>=0);
  CHECK(epoll_wait(ep,&out,1,0)==1 && out.events==EPOLLOUT);
  CHECK(close(ep)==0);
 } else if (!strcmp(argv[1],"splice")) {
  int q[2]; char buf[4]={0}; CHECK(pipe2(q,O_NONBLOCK)==0);
  n=reopen(p[1],O_RDONLY|O_NONBLOCK); CHECK(n>=0);
  other=reopen(q[0],O_WRONLY|O_NONBLOCK); CHECK(other>=0);
  CHECK(write(p[1],"abc",3)==3);
  CHECK(tee(n,other,3,SPLICE_F_NONBLOCK)==3);
  CHECK(read(q[0],buf,3)==3 && !memcmp(buf,"abc",3));
  CHECK(splice(n,0,other,0,3,SPLICE_F_NONBLOCK)==3);
  CHECK(read(q[0],buf,3)==3 && !memcmp(buf,"abc",3));
  CHECK(read(n,&c,1)==-1 && errno==EAGAIN);
  CHECK(splice(n,0,p[1],0,1,SPLICE_F_NONBLOCK)==-1 && errno==EINVAL);
  CHECK(tee(n,p[1],1,SPLICE_F_NONBLOCK)==-1 && errno==EINVAL);
  CHECK(close(q[0])==0 && close(q[1])==0);
 } else if (!strcmp(argv[1],"churn")) {
  pid_t child=fork(); CHECK(child>=0);
  for (int i=0;i<2000;i++) {
   int r=reopen(p[i%2],O_RDWR|O_NONBLOCK); CHECK(r>=0);
   int d=dup(r); CHECK(d>=0); CHECK(close(r)==0 && close(d)==0);
  }
  if (!child) _exit(0);
  int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
  CHECK(write(p[1],"c",1)==1 && read(p[0],&c,1)==1 && c=='c');
 } else if (!strcmp(argv[1],"exhaustion")) {
  struct rlimit lim={128,128}; int fd[128], count=0;
  CHECK(setrlimit(RLIMIT_NOFILE,&lim)==0);
  while ((n=reopen(p[0],O_RDONLY|O_NONBLOCK))>=0) { CHECK(count<128); fd[count++]=n; }
  CHECK(errno==EMFILE && count>0); n=-1;
  for (int i=0;i<count;i++) CHECK(close(fd[i])==0);
  CHECK(close(p[0])==0); p[0]=-1;
  CHECK(write(p[1],"x",1)==-1 && errno==EPIPE);
 } else if (!strcmp(argv[1],"async")) {
  sigset_t signals; sigemptyset(&signals); sigaddset(&signals,SIGIO);
  CHECK(sigprocmask(SIG_BLOCK,&signals,0)==0);
  struct timespec now={0,0}, wait={2,0};
  n=reopen(p[0],O_RDONLY|O_NONBLOCK); CHECK(n>=0);
  CHECK(fcntl(p[0],F_SETOWN,getpid())==0);
  CHECK(fcntl(n,F_GETOWN)==0 && fcntl(p[1],F_GETOWN)==0);
  CHECK(fcntl(n,F_SETOWN,getpid())==0);
  CHECK(fcntl(n,F_SETFL,O_NONBLOCK|O_ASYNC)==0);
  CHECK(fcntl(p[0],F_SETFL,O_NONBLOCK|O_ASYNC)==0);
  CHECK(fcntl(p[0],F_SETFL,O_NONBLOCK)==0);
  CHECK(write(p[1],"a",1)==1);
  CHECK(sigtimedwait(&signals,0,&wait)==SIGIO);
  CHECK(read(n,&c,1)==1 && c=='a');
  CHECK(sigtimedwait(&signals,0,&now)==-1 && errno==EAGAIN);
  other=dup(n); CHECK(other>=0);
  CHECK(fcntl(other,F_GETOWN)==getpid());
  CHECK(fcntl(other,F_SETOWN,0)==0 && fcntl(n,F_GETOWN)==0);
  CHECK(fcntl(p[0],F_GETOWN)==getpid());
  CHECK(fcntl(n,F_SETFL,O_NONBLOCK)==0);
  CHECK(write(p[1],"b",1)==1 && read(n,&c,1)==1 && c=='b');
  CHECK(sigtimedwait(&signals,0,&now)==-1 && errno==EAGAIN);
 } else if (!strcmp(argv[1],"full_writer")) {
  char block[4096]; memset(block,'x',sizeof(block));
  n=reopen(p[1],O_WRONLY|O_NONBLOCK); CHECK(n>=0);
  while (write(n,block,sizeof(block))==(ssize_t)sizeof(block)) {}
  CHECK(errno==EAGAIN);
  CHECK(close(p[0])==0); p[0]=-1;
  struct pollfd ready={.fd=n,.events=POLLOUT};
  CHECK(poll(&ready,1,0)==1 && ready.revents==POLLERR);
  int ep=epoll_create1(0); CHECK(ep>=0);
  struct epoll_event ev={.events=EPOLLOUT}, out;
  CHECK(epoll_ctl(ep,EPOLL_CTL_ADD,n,&ev)==0);
  CHECK(epoll_wait(ep,&out,1,0)==1 && out.events==EPOLLERR);
  CHECK(write(n,"x",1)==-1 && errno==EPIPE);
  other=reopen(n,O_RDONLY|O_NONBLOCK); CHECK(other>=0);
  CHECK(read(other,block,sizeof(block))==(ssize_t)sizeof(block));
  CHECK(poll(&ready,1,0)==1 && ready.revents==POLLOUT);
  CHECK(epoll_wait(ep,&out,1,0)==1 && out.events==EPOLLOUT);
  CHECK(close(ep)==0);
 } else if (!strcmp(argv[1],"metadata")) {
  struct stat st;
  n=reopen(p[0],O_RDWR|O_NONBLOCK); CHECK(n>=0);
  CHECK(fchmod(n,0400)==0);
  CHECK(fstat(p[1],&st)==0 && (st.st_mode&07777)==0400);
  other=reopen(p[1],O_RDONLY|O_NONBLOCK); CHECK(other>=0);
  CHECK(close(other)==0); other=-1;
  if (getuid()!=0) {
   CHECK(reopen(p[0],O_WRONLY|O_NONBLOCK)==-1 && errno==EACCES);
   CHECK(fchown(n,0,(gid_t)-1)==-1 && errno==EPERM);
  }
  CHECK(write(n,"m",1)==1 && read(n,&c,1)==1 && c=='m');
  CHECK(fchown(n,(uid_t)-1,getgid())==0);
  CHECK(fchmod(n,0600)==0);
  other=reopen(n,O_PATH); CHECK(other>=0);
  CHECK(syscall(SYS_fchmod,other,0666)==-1 && errno==EBADF);
  CHECK(syscall(SYS_fchown,other,getuid(),getgid())==-1 && errno==EBADF);
  if (getuid()==0) {
   CHECK(fchown(n,65534,65534)==0);
   CHECK(fstat(p[0],&st)==0 && st.st_uid==65534 && st.st_gid==65534);
   pid_t child=fork(); CHECK(child>=0);
   if (!child) {
    CHECK(setgid(65534)==0 && setuid(65534)==0);
    int r=reopen(p[0],O_RDWR|O_NONBLOCK); CHECK(r>=0);
    CHECK(fchmod(r,0660)==0); CHECK(close(r)==0); _exit(0);
   }
   int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
   CHECK(fstat(n,&st)==0 && (st.st_mode&07777)==0660);
  }
 } else if (!strcmp(argv[1],"permission")) {
  /* Inherited descriptors still work after losing the inode owner's uid. */
  if (getuid()==0) {
   pid_t child=fork(); CHECK(child>=0);
   if (!child) {
    CHECK(setgid(65534)==0 && setuid(65534)==0);
    CHECK(reopen(p[0],O_RDONLY|O_NONBLOCK)==-1 && errno==EACCES);
    CHECK(reopen(p[1],O_WRONLY|O_NONBLOCK)==-1 && errno==EACCES);
    int path=reopen(p[0],O_PATH); CHECK(path>=0); CHECK(close(path)==0);
    CHECK(write(p[1],"p",1)==1); _exit(0);
   }
   int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
   CHECK(read(p[0],&c,1)==1 && c=='p');
  } else { n=reopen(p[0],O_RDONLY|O_NONBLOCK); CHECK(n>=0); }
 } else { fprintf(stderr,"unknown pipe case %s\n",argv[1]); return 2; }
 if (other>=0) CHECK(close(other)==0);
 if (n>=0) CHECK(close(n)==0);
 if (p[0]>=0) CHECK(close(p[0])==0);
 if (p[1]>=0) CHECK(close(p[1])==0);
 printf("PIPE_REOPEN_PASS %s\n",argv[1]); return 0;
}
