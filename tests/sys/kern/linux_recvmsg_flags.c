/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 recvmsg output flags. Run only in disposable guests. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc,char **argv)
{
 const int types[]={SOCK_STREAM,SOCK_DGRAM,SOCK_SEQPACKET};
 int failed=0;
 /* The optional mode reproduces the separate native SEQPACKET record gap. */
 int sequence=argc==2 && !strcmp(argv[1],"seqpacket");
 if(argc>2 || (argc==2 && !sequence)) return 2;
 for(unsigned t=sequence?2:0;t<(sequence?3:2);t++) {
  for(int eor=0;eor<2;eor++) {
   int pair[2]; char data[8]={0};
   if(socketpair(AF_UNIX,types[t],0,pair)!=0) return 1;
   ssize_t n=send(pair[0],data,sizeof(data),eor?MSG_EOR:0);
   if(n!=sizeof(data)) {
    printf("RECVMSG_SEND_ERROR %d %d %zd %d\n",types[t],eor,n,errno);
    failed=1; close(pair[0]); close(pair[1]); continue;
   }
   struct iovec iov={data,2};
   struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
   n=recvmsg(pair[1],&msg,MSG_PEEK|MSG_DONTWAIT);
   printf("RECVMSG_FLAGS %d %d peek %zd %u\n",types[t],eor,n,msg.msg_flags);
   if(n!=2 || msg.msg_flags!=(types[t]==SOCK_STREAM?0:MSG_TRUNC)) failed=1;
   iov.iov_len=sizeof(data); msg.msg_flags=0;
   n=recvmsg(pair[1],&msg,MSG_CMSG_CLOEXEC);
   printf("RECVMSG_FLAGS %d %d consume %zd %u\n",types[t],eor,n,msg.msg_flags);
   if(n!=sizeof(data) || msg.msg_flags!=MSG_CMSG_CLOEXEC) failed=1;
   if(close(pair[0]) || close(pair[1])) return 2;
  }
 }
 if(sequence) {
  int pair[2]; char data[8],a[8],b[8];
  memset(a,'A',sizeof(a)); memset(b,'B',sizeof(b));
  if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK,0,pair)) return 3;
  if(send(pair[0],a,sizeof(a),0)!=sizeof(a) || send(pair[0],b,sizeof(b),0)!=sizeof(b)) return 4;
  struct iovec iov={data,2}; struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
  ssize_t first=recvmsg(pair[1],&msg,0); unsigned flags=msg.msg_flags;
  ssize_t next=recv(pair[1],data,sizeof(data),0);
  int intact=next==sizeof(data) && !memcmp(data,b,sizeof(b));
  ssize_t trailing=recv(pair[1],data,sizeof(data),0); int end_error=errno;
  printf("RECVMSG_RECORDS %zd %u %zd %d %zd %d\n",first,flags,next,intact,trailing,end_error);
  if(first!=2 || flags!=MSG_TRUNC || !intact || trailing!=-1 || end_error!=EAGAIN) failed=1;
  if(close(pair[0]) || close(pair[1])) return 5;
 }
 return failed;
}
