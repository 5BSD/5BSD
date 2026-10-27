# SPDX-License-Identifier: BSD-2-Clause
"""Actual io.read binding with a native Lua 5.4 library; file I/O injected."""
import argparse
from pathlib import Path
import subprocess,tempfile
ROOT=Path(__file__).resolve().parents[3]
PRE=r"""
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <lua.h>
#include <lauxlib.h>
#undef ferror
#define FILE LoaderFile
#define fread test_fread
#define ferror test_ferror
typedef struct {size_t size;int error;} LoaderFile;
static int fail_alloc,fail_read,allocations,reads;
static size_t test_fread(void *p,size_t size,size_t count,FILE *f) {
 assert(size==1);reads++;if(fail_read){f->error=EIO;return 0;}
 memset(p,'x',count);return count;
}
static int test_ferror(FILE *f) {return f->error;}
static void *test_malloc(size_t n) {allocations++;if(fail_alloc)return NULL;return malloc(n);}
#define malloc test_malloc
"""
MAIN=r"""
int main(void) {
 lua_State *L=luaL_newstate();assert(L);
 for(int scenario=0;scenario<11;scenario++) {
  lua_settop(L,0);FILE file={8,0};FILE **handle=lua_newuserdatauv(L,sizeof(FILE *),0);*handle=&file;
  fail_alloc=fail_read=allocations=reads=0;
  if(scenario==1)lua_pushinteger(L,4);
  if(scenario==2)lua_pushinteger(L,-1);
  if(scenario==3)lua_pushnumber(L,0.5);
  if(scenario==4)lua_pushnumber(L,INFINITY);
  if(scenario==5)lua_pushnumber(L,NAN);
  if(scenario==6)fail_alloc=1;
  if(scenario==7)fail_read=1;
  if(scenario==8)lua_pushinteger(L,0);
  if(scenario==9)file.size=SIZE_MAX;
  if(scenario==10)file.error=EIO;
  assert(lua_readfile(L)==2);
  if(scenario==0 || scenario==1 || scenario==8) {
   size_t n;const char *s=lua_tolstring(L,-2,&n);assert(s);
   assert(n==(scenario==0?8:scenario==1?4:0));
   assert(lua_tointeger(L,-1)==(lua_Integer)n);
  } else assert(lua_isnil(L,-2) && lua_tointeger(L,-1)==0);
  if((scenario>=2 && scenario<=5) || scenario>=8)assert(!reads && !allocations);
 }
 lua_close(L);return 0;
}
"""
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lua-library',type=Path,required=True)
    parser.add_argument('--lua-include',type=Path,required=True)
    args=parser.parse_args()
    source=(ROOT/'stand/liblua/lutils.c').read_text();start=source.index('static int\nlua_readfile(')
    function=source[start:source.index('\n}\n',start)+3]
    with tempfile.TemporaryDirectory() as directory:
        c=Path(directory)/'test.c';binary=Path(directory)/'test';c.write_text(PRE+function+MAIN)
        subprocess.run(['cc','-Wall','-Wextra','-Werror','-I'+str(args.lua_include.resolve(strict=True)),
            str(c),str(args.lua_library.resolve(strict=True)),'-lm','-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,cwd=directory,timeout=10)
    print('PASS: io.read sizes, allocation/read errors and empty input with native Lua API')
if __name__=='__main__':main()
