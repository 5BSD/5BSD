#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Run the real control CLI against isolated Unix-socket protocol fixtures."""
import hashlib
import errno
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading

out,binary = (Path(p).resolve() for p in sys.argv[1:])
assert all(p.is_relative_to('/usr/obj') for p in (out,binary)) and not out.exists()
out.mkdir(parents=True)
root = Path(__file__).resolve().parents[3]
shim = out/'redirect.c'
shim.write_text('''#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dtraced.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
static int fault_fired, tracked_socket = -1;
static void *tracked_name;
static size_t sent_bytes, received_bytes;
static int selected(const char *name) {
 const char *mode = getenv("HYPERTRACE_TEST_FAULT");
 return !fault_fired && mode && strcmp(mode,name) == 0;
}
static void hit(const char *name) {
 fault_fired = 1;
 (void)write(2,"HTCTL_FAULT_HIT=",16);
 (void)write(2,name,strlen(name));
 (void)write(2,"\\n",1);
}
char *strdup(const char *value) {
 char *(*real_strdup)(const char *) = dlsym(RTLD_NEXT,"strdup");
 if ((!strcmp(value,"first") && selected("strdup-first")) ||
     (!strcmp(value,"second") && selected("strdup-second"))) {
  hit(!strcmp(value,"first") ? "strdup-first" : "strdup-second");
  errno = ENOMEM; return NULL;
 }
 if (!real_strdup) { errno = ENOMEM; return NULL; }
 char *result = real_strdup(value);
 if (!strcmp(value,"first") && selected("strdup-second")) tracked_name = result;
 return result;
}
void free(void *pointer) {
 void (*real_free)(void *) = dlsym(RTLD_NEXT,"free");
 if (!real_free) abort();
 if (pointer && pointer == tracked_name) {
  tracked_name = NULL;
  if (fault_fired) (void)write(2,"HTCTL_NAME_FREED\\n",17);
 }
 real_free(pointer);
}
int socket(int domain, int type, int protocol) {
 int (*real_socket)(int,int,int) = dlsym(RTLD_NEXT,"socket");
 if (domain == AF_UNIX && selected("socket")) {
  hit("socket"); errno = EMFILE; return -1;
 }
 if (!real_socket) { errno = EPERM; return -1; }
 int result = real_socket(domain,type,protocol);
 if (domain == AF_UNIX) tracked_socket = result;
 return result;
}
ssize_t send(int fd, const void *buffer, size_t length, int flags) {
 int forced_short = 0;
 ssize_t (*real_send)(int,const void *,size_t,int) = dlsym(RTLD_NEXT,"send");
 const char *mode = getenv("HYPERTRACE_TEST_FAULT");
 if (fd == tracked_socket && selected("send-interrupted")) {
  hit("send-interrupted"); errno = EINTR; return -1;
 }
 if (fd == tracked_socket && length > 1 && selected("send-short")) {
  length = 1; forced_short = 1;
 }
 size_t boundary = SIZE_MAX;
 if (mode && !strcmp(mode,"send-handshake")) boundary = 0;
 else if (mode && !strcmp(mode,"send-frame-size")) boundary = 160;
 else if (mode && !strcmp(mode,"send-header")) boundary = 168;
 else if (mode && !strcmp(mode,"send-name-size")) boundary = 688;
 else if (mode && !strcmp(mode,"send-name-data")) boundary = 696;
 if (fd == tracked_socket && boundary != SIZE_MAX && !fault_fired) {
  if (sent_bytes == boundary) { hit(mode); errno = EPIPE; return -1; }
  if (length > boundary - sent_bytes) length = boundary - sent_bytes;
 }
 if (!real_send) { errno = EPERM; return -1; }
 ssize_t result = real_send(fd,buffer,length,flags);
 if (forced_short && result == 1) {
  hit("send-short"); (void)write(2,"HTCTL_SHORT_TRANSFER\\n",21);
 }
 if (fd == tracked_socket && result > 0) sent_bytes += (size_t)result;
 return result;
}
ssize_t recv(int fd, void *buffer, size_t length, int flags) {
 int forced_short = 0;
 ssize_t (*real_recv)(int,void *,size_t,int) = dlsym(RTLD_NEXT,"recv");
 if (fd == tracked_socket && selected("recv-interrupted")) {
  hit("recv-interrupted"); errno = EINTR; return -1;
 }
 if (fd == tracked_socket && length > 1 && selected("recv-short")) {
  length = 1; forced_short = 1;
 }
 if (fd == tracked_socket && received_bytes == 160 && selected("recv-ack")) {
  hit("recv-ack"); errno = EIO; return -1;
 }
 if (!real_recv) { errno = EPERM; return -1; }
 ssize_t result = real_recv(fd,buffer,length,flags);
 if (forced_short && result == 1) {
  hit("recv-short"); (void)write(2,"HTCTL_SHORT_TRANSFER\\n",21);
 }
 if (fd == tracked_socket && result > 0) received_bytes += (size_t)result;
 return result;
}
int shutdown(int fd, int how) {
 int (*real_shutdown)(int,int) = dlsym(RTLD_NEXT,"shutdown");
 if (fd == tracked_socket && fault_fired && how == SHUT_RDWR)
  (void)write(2,"HTCTL_SOCKET_SHUTDOWN\\n",22);
 if (!real_shutdown) { errno = EPERM; return -1; }
 return real_shutdown(fd,how);
}
int close(int fd) {
 int (*real_close)(int) = dlsym(RTLD_NEXT,"close");
 if (fd == tracked_socket) {
  tracked_socket = -1;
  if (fault_fired) (void)write(2,"HTCTL_SOCKET_CLOSED\\n",20);
 }
 if (!real_close) { errno = EPERM; return -1; }
 return real_close(fd);
}
int clock_gettime(clockid_t clock, struct timespec *value) {
 int (*real_clock)(clockid_t,struct timespec *) = dlsym(RTLD_NEXT,"clock_gettime");
 const char *mode = getenv("HYPERTRACE_TEST_FAULT");
 if (clock == CLOCK_MONOTONIC && mode && !strncmp(mode,"clock-",6) && !fault_fired) {
  hit(mode);
  if (!strcmp(mode,"clock-error")) { errno = EIO; return -1; }
  value->tv_sec = 0; value->tv_nsec = 0;
  if (!strcmp(mode,"clock-negative-seconds")) value->tv_sec = -1;
  else if (!strcmp(mode,"clock-negative-nanoseconds")) value->tv_nsec = -1;
  else if (!strcmp(mode,"clock-large-nanoseconds")) value->tv_nsec = 1000000000L;
  else if (!strcmp(mode,"clock-overflow")) value->tv_sec = INT64_MAX;
  else if (!strcmp(mode,"clock-deadline-overflow")) value->tv_sec = INT64_MAX / 1000;
  else { errno = EINVAL; return -1; }
  return 0;
 }
 if (!real_clock) { errno = EPERM; return -1; }
 return real_clock(clock,value);
}
int connect(int fd, const struct sockaddr *address, socklen_t length) {
 const char *path = getenv("HYPERTRACE_TEST_SOCKET");
 struct sockaddr_un replacement = { .sun_family = AF_UNIX };
 int (*real_connect)(int,const struct sockaddr *,socklen_t) = dlsym(RTLD_NEXT,"connect");
 if (!real_connect || !path || strncmp(path,"/tmp/htctl-",11) ||
     length < offsetof(struct sockaddr_un,sun_path)+1 || address->sa_family != AF_UNIX ||
     strcmp(((const struct sockaddr_un *)address)->sun_path,DTRACED_SOCKPATH) ||
     strlcpy(replacement.sun_path,path,sizeof(replacement.sun_path)) >= sizeof(replacement.sun_path)) {
  errno = EPERM; return -1;
 }
 replacement.sun_len = SUN_LEN(&replacement);
 return real_connect(fd,(const struct sockaddr *)&replacement,replacement.sun_len);
}
''')
subprocess.run(['/usr/bin/cc','-shared','-fPIC','-I'+str(root/'usr.sbin/dtraced'),str(shim),'-o',str(out/'redirect.so')],check=True)
# Fixed public wire constants; changes require reviewing this independent peer.
VERSION, HELLO_SIZE, HEADER_SIZE = 67,160,520
stats = (1,17,1<<40,(1<<64)-1)
expected_stats = ''.join(f'{label}: {value}\n' for label,value in zip(
    ('forwarder channels','outbound deliveries','installed deliveries','revoked deliveries'),stats))
cases = []
def add(name,args,status,mode=None,names=(),kind=3,diagnostic='',fault=None):
    cases.append(dict(name=name,args=args,status=status,mode=mode,names=names,kind=kind,diagnostic=diagnostic,fault=fault))
add('help',['--help'],0,diagnostic='Usage:')
add('no-action',[],64,diagnostic='Usage:')
add('unknown',['--not-an-option'],1,diagnostic='Usage:')
add('two-actions',['--show-stats','--cleanup-state'],64,diagnostic='Usage:')
add('repeat-cleanup',['--cleanup-state','--cleanup-state'],64,diagnostic='Usage:')
add('positional-without-action',['first'],64,diagnostic='invalid VM names')
add('duplicate-names',['--cleanup-state=first','second'],64,diagnostic='invalid VM names')
add('too-many-positionals',['--show-stats','first','second'],64,diagnostic='invalid VM names')
for option in ('cleanup-state','show-stats'):
    for label,value in [('empty',''),('leading',',a'),('trailing','a,'),('double','a,,b'),('long','x'*4096),('many',','.join(['a']*4097))]:
        add(option+'-'+label,['--'+option+'='+value],64,diagnostic='invalid VM names')
add('missing-socket',['--show-stats'],69,diagnostic='connection failed')
for fault in ('socket','clock-error','clock-negative-seconds','clock-negative-nanoseconds',
    'clock-large-nanoseconds','clock-overflow','clock-deadline-overflow'):
    error = errno.EMFILE if fault == 'socket' else errno.EIO if fault == 'clock-error' else errno.EOVERFLOW
    add('fault-'+fault,['--show-stats'],69,diagnostic='connection failed: '+os.strerror(error),fault=fault)
for fault in ('strdup-first','strdup-second'):
    add('fault-'+fault,['--cleanup-state=first,second'],64,
        diagnostic='invalid VM names: '+os.strerror(errno.ENOMEM),fault=fault)
add('cleanup-all',['--cleanup-state'],0,'ok')
add('cleanup-inline',['--cleanup-state=first,second'],0,'ok',('first','second'))
add('cleanup-positional',['--cleanup-state','first,second'],0,'fragment',('first','second'))
add('cleanup-longest-name',['--cleanup-state='+'x'*4095],0,'ok',('x'*4095,))
add('cleanup-most-names',['--cleanup-state='+','.join(['a']*4096)],0,'ok',tuple(['a']*4096))
add('stats-all',['--show-stats'],0,'ok',kind=15)
add('stats-named',['--show-stats=first,second'],0,'fragment',('first','second'),15)
for mode in ('wrong-version','wrong-kind','nonzero-subs','nonzero-ident','nonzero-session','short-hello'):
    add(mode,['--show-stats'],69,mode,kind=15,diagnostic='connection failed')
for mode in ('nack','close-ack','short-stats'):
    add(mode,['--show-stats=first'],74,mode,('first',),15,'statistics failed')
add('cleanup-nack',['--cleanup-state'],74,'nack',diagnostic='cleanup failed')
exchange_boundaries = {'send-handshake':0,'send-frame-size':160,'send-header':168,
    'send-name-size':688,'send-name-data':696,'recv-ack':702}
for fault in exchange_boundaries:
    status = 69 if fault == 'send-handshake' else 74
    diagnostic = 'connection failed: ' if status == 69 else 'statistics failed: '
    error = errno.EIO if fault == 'recv-ack' else errno.EPIPE
    add('fault-'+fault,['--show-stats=first'],status,'exchange-fault',('first',),15,
        diagnostic+os.strerror(error),fault=fault)


for fault in ('send-interrupted','recv-interrupted','send-short','recv-short'):
    add('recover-'+fault,['--show-stats=first'],0,'ok',('first',),15,fault=fault)

def receive(peer,length):
    data = bytearray()
    while len(data)<length:
        chunk=peer.recv(length-len(data))
        assert chunk,'unexpected EOF'
        data.extend(chunk)
    return bytes(data)

def server(listener,case,errors,observed):
    try:
        peer,_=listener.accept()
        with peer:
            peer.settimeout(4)
            hello=bytearray(struct.pack('<IIQ',3,VERSION,0)+bytes(144))
            mode=case['mode']
            if mode=='wrong-version':struct.pack_into('<I',hello,4,VERSION-1)
            if mode=='wrong-kind':struct.pack_into('<I',hello,0,2)
            if mode=='nonzero-subs':hello[8]=1
            if mode=='nonzero-ident':hello[16]=1
            if mode=='nonzero-session':hello[144]=1
            if mode=='short-hello':peer.sendall(hello[:10]);return
            if mode=='fragment':
                for b in hello:peer.sendall(bytes([b]))
            else:peer.sendall(hello)
            if mode == 'exchange-fault':
                received = bytearray()
                while True:
                    chunk = peer.recv(4096)
                    if not chunk:break
                    received.extend(chunk)
                boundary = exchange_boundaries[case['fault']]
                assert len(received) == boundary, (len(received),boundary)
                if boundary:
                    client = received[:HELLO_SIZE]
                    assert struct.unpack_from('<IIQ',client)==(1,VERSION,1)
                    ident = client[16:144];end = ident.index(0)
                    assert ident[:end].startswith(b'dtracedctl-') and ident[end:]==bytes(128-end)
                    assert client[144:]==bytes(16)
                    header = bytearray(HEADER_SIZE)
                    struct.pack_into('<Q',header,0,15);struct.pack_into('<Q',header,304,1)
                    request = struct.pack('<Q',HEADER_SIZE+14)+header+struct.pack('<Q',6)+b'first\0'
                    assert received[HELLO_SIZE:] == request[:boundary-HELLO_SIZE]
                observed.update(bytes_before_failure=len(received),fault=case['fault'])
                return
            if mode.startswith(('wrong-','nonzero-')):
                assert peer.recv(1)==b'';return
            client=receive(peer,HELLO_SIZE)
            assert struct.unpack_from('<IIQ',client)==(1,VERSION,1)
            ident=client[16:144];end=ident.index(0)
            assert ident[:end].startswith(b'dtracedctl-') and ident[end:]==bytes(128-end) and client[144:]==bytes(16)
            length=struct.unpack('<Q',receive(peer,8))[0]
            assert HEADER_SIZE <= length <= HEADER_SIZE+4096*(8+4096)
            frame=receive(peer,length)
            expected_header=bytearray(HEADER_SIZE)
            struct.pack_into('<Q',expected_header,0,case['kind'])
            struct.pack_into('<Q',expected_header,304,len(case['names']))
            assert frame[:HEADER_SIZE]==expected_header
            offset=HEADER_SIZE;names=[]
            for expected in case['names']:
                size=struct.unpack_from('<Q',frame,offset)[0];offset+=8
                value=frame[offset:offset+size];offset+=size
                assert value==expected.encode()+b'\0';names.append(expected)
            assert offset==len(frame)
            observed.update(frame_bytes=length,name_count=len(names),kind=case['kind'])
            if mode=='close-ack':return
            peer.sendall(b'\0' if mode=='nack' else b'\1')
            if mode=='nack':return
            if case['kind']==15:
                response=struct.pack('<4Q',*stats)
                if mode=='short-stats':response=response[:-1]
                if mode=='fragment':
                    for b in response:peer.sendall(bytes([b]))
                else:peer.sendall(response)
    except Exception as exc:errors.append(repr(exc))

results=[]
with tempfile.TemporaryDirectory(prefix='htctl-',dir='/tmp') as temp:
    path=str(Path(temp)/'peer.sock')
    for case in cases:
        errors=[];observed={};listener=None;thread=None
        if case['mode']:
            listener=socket.socket(socket.AF_UNIX);listener.bind(path);listener.listen(1);listener.settimeout(5)
            thread=threading.Thread(target=server,args=(listener,case,errors,observed));thread.start()
        env=dict(os.environ,LD_PRELOAD=str(out/'redirect.so'),HYPERTRACE_TEST_SOCKET=path,HYPERTRACE_TEST_FAULT=case['fault'] or '')
        try:
            run=subprocess.run([str(binary),*case['args']],env=env,capture_output=True,text=True,timeout=12)
        finally:
            if thread:thread.join(6)
            if listener:listener.close();Path(path).unlink()
        passed=run.returncode==case['status'] and case['diagnostic'] in run.stderr and not errors
        if case['fault']:
            passed=passed and run.stderr.count('HTCTL_FAULT_HIT='+case['fault']+'\n') == 1
            passed=passed and run.stderr.count('HTCTL_SOCKET_CLOSED\n') == (1 if case['fault'].startswith(('clock-','send-','recv-')) else 0)
            passed=passed and run.stderr.count('HTCTL_NAME_FREED\n') == (1 if case['fault']=='strdup-second' else 0)
            passed=passed and run.stderr.count('HTCTL_SHORT_TRANSFER\n') == (1 if case['fault'] in ('send-short','recv-short') else 0)
            passed=passed and run.stderr.count('HTCTL_SOCKET_SHUTDOWN\n') == (1 if case['fault'] in exchange_boundaries and case['fault']!='send-handshake' else 0)
        else:
            passed=passed and 'HTCTL_FAULT_HIT=' not in run.stderr
        if thread:passed=passed and not thread.is_alive()
        if case['status']==0 and case['kind']==15:passed=passed and run.stdout==expected_stats
        elif case['status']==0:passed=passed and run.stdout==''
        passed=passed and 'LLVM Profile Error' not in run.stderr
        results.append(dict(case=case['name'],status=run.returncode,stdout=run.stdout,stderr=run.stderr,
            peer_errors=errors,observed=observed,passed=passed))
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
(out/'provenance.json').write_text(json.dumps({'sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()
    for p in (binary,Path(__file__).resolve(),shim,root/'usr.sbin/dtracedctl/dtracedctl.c',
        root/'usr.sbin/dtraced/dtraced.h',root/'usr.sbin/dtraced/dtraced_wire.h',root/'usr.sbin/dtraced/dtraced_io.h')},
    'scope':'actual CLI; connect redirected exclusively to temporary Unix fixture; no installed daemon'},indent=2)+'\n')
for r in results:
    if not r['passed']:print(json.dumps(r))
print('Control CLI:',len(results),'cases;',sum(not r['passed'] for r in results),'failures')
raise SystemExit(not all(r['passed'] for r in results))
