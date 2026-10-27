# SPDX-License-Identifier: BSD-2-Clause
"""Native streaming-verifier cost probe; not firmware/performance acceptance."""
import argparse
import hashlib
import json
import statistics
import subprocess
import tempfile
from pathlib import Path
import verified_replay_test as replay

GLUE = r'''
#include <fcntl.h>
#include <time.h>
static size_t input_bytes, input_calls, seeks;
static ssize_t measured_read(int fd,void *buffer,size_t count) {
 ssize_t n=read(fd,buffer,count);input_calls++;if(n>0)input_bytes+=n;return n;
}
static off_t measured_seek(int fd,off_t offset,int whence) {
 seeks++;return lseek(fd,offset,whence);
}
#define read measured_read
#define lseek measured_seek
static double seconds(clockid_t clock) {
 struct timespec time;assert(clock_gettime(clock,&time)==0);
 return time.tv_sec+time.tv_nsec/1e9;
}
'''
MAIN = r'''
int main(int argc,char **argv) {
 assert(argc==5);
 int fd=open(argv[1],O_RDONLY);assert(fd>=0);
 struct stat st;assert(fstat(fd,&st)==0 && st.st_size>=PAGE_SIZE);
 int mode=atoi(argv[2]);assert(mode>=0 && mode<=3);
 for(int i=0;i<32;i++){unsigned value;assert(sscanf(argv[3]+2*i,"%2x",&value)==1);expected[i]=value;}
 unsigned replays=strtoul(argv[4],NULL,10);
 unsigned char buffer[PAGE_SIZE],digest[32];ssize_t n;
 double wall=seconds(CLOCK_MONOTONIC),cpu=seconds(CLOCK_PROCESS_CPUTIME_ID);
 size_t table=0,context=0;
 if(mode==0) {
  br_sha256_context hash;br_sha256_init(&hash);
  while((n=read(fd,buffer,sizeof(buffer)))>0)br_sha256_update(&hash,buffer,n);
  assert(n==0);br_sha256_out(&hash,digest);assert(memcmp(digest,expected,32)==0);
 } else {
  struct vectx *ctx=calloc(1,sizeof(*ctx));assert(ctx);context=sizeof(*ctx);
  ctx->vec_fd=fd;ctx->vec_path=argv[1];ctx->vec_size=st.st_size;
  ctx->vec_md=&br_sha256_vtable;ctx->vec_hashsz=32;ctx->vec_severity=VE_MUST;
  ctx->vec_md->init(&ctx->vec_ctx.vtable);
  if(mode==3)assert(vectx_set_sequential(ctx)==0);
  while((n=vectx_read(ctx,buffer,sizeof(buffer)))>0){}
  assert(n==0);
  if(mode==2) {
   uint64_t random=1;
   for(unsigned i=0;i<replays;i++) {
    random=random*6364136223846793005ULL+1;
    off_t offset=random%((uint64_t)st.st_size-17);
    assert(vectx_lseek(ctx,offset,SEEK_SET)==offset);
    assert(vectx_read(ctx,buffer,17)==17);
    for(int j=0;j<17;j++)assert(buffer[j]==(offset+j)%251);
   }
  }
  table=ctx->vec_pages_capacity;
  assert(vectx_close(ctx,"cost probe")==0);
 }
 cpu=seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu;wall=seconds(CLOCK_MONOTONIC)-wall;
 assert(close(fd)==0);
 printf("{\"mode\":%d,\"cpu_seconds\":%.9f,\"wall_seconds\":%.9f,"
  "\"input_bytes\":%zu,\"input_calls\":%zu,\"seeks\":%zu,"
  "\"digest_capacity\":%zu,\"context_bytes\":%zu}\n",
  mode,cpu,wall,input_bytes,input_calls,seeks,table,context);
 return 0;
}
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bearssl-library',type=Path,required=True)
    parser.add_argument('--work-dir',type=Path,required=True)
    parser.add_argument('--size-bytes',type=int,default=32*1024*1024)
    parser.add_argument('--iterations',type=int,default=5)
    parser.add_argument('--replay-reads',type=int,default=1024)
    args=parser.parse_args()
    if args.size_bytes<4096 or args.iterations<1 or not 0<=args.replay_reads<=1000000:
        parser.error('size must be >=4096, iterations positive, replay reads in 0..1000000')
    library=args.bearssl_library.resolve(strict=True)
    source=(replay.ROOT/'lib/libsecureboot/vectx.c').read_text()
    start=source.index('struct vectx {')
    parts=[source[start:source.index('\n};',start)+3]]
    for signature in ('void\nvectx_discard(', 'int\nvectx_set_sequential(', 'static int\nvectx_record(', 'static ssize_t\nvectx_replay(',
                      'ssize_t\nvectx_read(', 'off_t\nvectx_lseek(', 'int\nvectx_close('):
        start=source.index(signature);parts.append(source[start:source.index('\n}\n',start)+3])
    directory=Path(tempfile.mkdtemp(prefix='vectx-cost-',dir=args.work_dir.resolve(strict=True)))
    c=directory/'probe.c';binary=directory/'probe';payload=directory/'payload'
    c.write_text(replay.PREAMBLE+GLUE+'\n'.join(parts)+MAIN)
    command=['cc','-O2','-Wall','-Wextra','-Werror',
             '-I'+str(replay.ROOT/'contrib/bearssl/inc'),
             '-I'+str(replay.ROOT/'lib/libsecureboot/h'),str(c),str(library),'-o',str(binary)]
    subprocess.run(command,check=True)
    digest=hashlib.sha256();chunk=bytes(range(251))*4096;remaining=args.size_bytes
    with payload.open('xb') as file:
        while remaining:
            data=chunk[:min(len(chunk),remaining)];file.write(data);digest.update(data);remaining-=len(data)
    rows=[]
    for repeat in range(args.iterations):
        for step in range(4):
            mode=(repeat+step)%4
            result=subprocess.run([str(binary),str(payload),str(mode),digest.hexdigest(),str(args.replay_reads)],
                                  check=True,capture_output=True,text=True,timeout=300)
            row=json.loads(result.stdout);row['iteration']=repeat;rows.append(row)
            if mode==3:assert row['digest_capacity']==0
            if mode!=2:assert row['input_bytes']==args.size_bytes
            else:assert args.size_bytes<=row['input_bytes']<=args.size_bytes+args.replay_reads*8192
    medians={str(mode):{metric:statistics.median(r[metric] for r in rows if r['mode']==mode)
             for metric in ('cpu_seconds','wall_seconds')} for mode in range(4)}
    report={'scope':'native host, warm/cache state uncontrolled, injected trusted digest; not firmware acceptance',
            'modes':{'0':'single-pass SHA256 sequential baseline','1':'actual vectx sequential',
                     '2':'actual vectx sequential plus deterministic 17-byte replays',
                     '3':'actual vectx with enforced sequential restriction'},
            'inputs':vars(args)|{'bearssl_library':str(library),'work_dir':str(directory)},
            'compiler_command':command,'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'bearssl_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
            'payload_sha256':digest.hexdigest(),'rows':rows,'medians':medians,
            'sequential_cpu_ratio':medians['1']['cpu_seconds']/medians['0']['cpu_seconds'],
            'restricted_cpu_ratio':medians['3']['cpu_seconds']/medians['0']['cpu_seconds']}
    (directory/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'results':str(directory/'results.json'),'medians':medians,
                      'sequential_cpu_ratio':report['sequential_cpu_ratio'],
                      'restricted_cpu_ratio':report['restricted_cpu_ratio']},indent=2))

if __name__=='__main__':main()
