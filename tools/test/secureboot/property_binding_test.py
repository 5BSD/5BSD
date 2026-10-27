# SPDX-License-Identifier: BSD-2-Clause
"""Native-property branch identity/lifetime checks; not a ZFS race test."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(os.environ.get('ZFS_PROPERTY_SOURCE', str(ROOT / 'sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c')))

class PropertyBinding(unittest.TestCase):
    def test_native_property_uses_held_object(self):
        text=SOURCE.read_text()
        begin=text.index('static int\nzfshandle_op_get_one_prop(')
        start=text.index('\t/* Native property:',begin)
        end=text.index('\n}\n',start)
        branch=text[start:end]
        prelude=r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#define PROP_TYPE_STRING 1
#define ZPROP_SRC_DEFAULT 1
#define ZPROP_SRC_LOCAL 2
#define ZPROP_SRC_INHERITED 3
#define FTAG NULL
typedef int dsl_pool_t;
typedef struct { int identity; } dsl_dataset_t;
typedef int zfshandle_t;
struct zfd_get_one_prop_args { char zgo_name[32],zgo_strval[64]; uint64_t zgo_intval; int zgo_is_string,zgo_source; };
static dsl_pool_t pool;
static dsl_dataset_t dataset={17};
static int held,holds,releases,hold_error,read_error,source_mode;
static int zfs_prop_get_type(int prop) { return prop; }
static int zfshandle_hold(zfshandle_t *handle,const void *tag,dsl_pool_t **dp,dsl_dataset_t **ds) {
 (void)handle;(void)tag;assert(!held);holds++;
 if(hold_error)return hold_error;
 held=1;*dp=&pool;*ds=&dataset;return 0;
}
static void zfshandle_rele(dsl_pool_t *dp,dsl_dataset_t *ds,const void *tag) {
 (void)tag;assert(held && dp==&pool && ds==&dataset);held=0;releases++;
}
static void dsl_dataset_name(dsl_dataset_t *ds,char *name) {
 assert(held && ds==&dataset);strcpy(name,"pool/current");
}
static int dsl_prop_get_ds(dsl_dataset_t *ds,const char *prop,int width,int count,void *value,char *setpoint) {
 (void)prop;assert(held && ds==&dataset && ds->identity==17);
 if(read_error)return read_error;
 if(width==1) {assert(count==64);strcpy(value,"held-value");}
 else {assert(width==sizeof(uint64_t) && count==1);*(uint64_t *)value=73;}
 strcpy(setpoint,source_mode==0?"":source_mode==1?"pool/current":"pool");return 0;
}
/* A name can now select a replacement dataset. No such lookup is permitted. */
static int dsl_prop_get(const char *name,const char *prop,int width,int count,void *value,char *setpoint) {
 (void)name;(void)prop;(void)width;(void)count;(void)value;(void)setpoint;assert(false);return EIO;
}
static int dsl_prop_get_integer(const char *name,const char *prop,uint64_t *value,char *setpoint) {
 return dsl_prop_get(name,prop,8,1,value,setpoint);
}
'''
        wrapper='static int query(zfshandle_t *zh, struct zfd_get_one_prop_args *args,int prop) {\nchar name[64]="pool/stale",setpoint[64];int error;\n'+branch+'\n}\n'
        main=r'''
int main(void) {
 zfshandle_t handle=0;struct zfd_get_one_prop_args args={0};
 for(int type=1;type<=2;type++) for(source_mode=0;source_mode<3;source_mode++) {
  holds=releases=0;assert(query(&handle,&args,type)==0);
  assert(holds==1 && releases==1 && held==0);
  assert(args.zgo_source==source_mode+1);
  assert(args.zgo_is_string==(type==1));
  if(type==1)assert(strcmp(args.zgo_strval,"held-value")==0);else assert(args.zgo_intval==73);
 }
 holds=releases=0;hold_error=ENXIO;assert(query(&handle,&args,1)==ENXIO);
 assert(holds==1 && releases==0 && !held);hold_error=0;
 for(int type=1;type<=2;type++) {
  holds=releases=0;read_error=EIO;assert(query(&handle,&args,type)==EIO);
  assert(holds==1 && releases==1 && !held);
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='property-binding-') as directory:
            source=Path(directory)/'test.c';binary=Path(directory)/'test'
            source.write_text(prelude+wrapper+main)
            for command in (['cc','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter',str(source),'-o',str(binary)],[str(binary)]):
                result=subprocess.run(command,capture_output=True,text=True,cwd=directory)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__=='__main__': unittest.main()
