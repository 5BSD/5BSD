/* Generated automatically */
static HashNode getparamnode(HashTable ht,const char*nam);
static void scancopyparams(HashNode hn,UNUSED(int flags));
static void scanparamvals(HashNode hn,int flags);
static char**getvaluearr(Value v);
static void assigngetset(Param pm);
static void shempty(void);
static zlong getarg(char**str,int*inv,Value v,int a2,zlong*w,int*prevcharlen,int*nextcharlen,int flags);
static void assignstrvalue(Value v,char*val,int flags);
static void check_warn_pm(Param pm,const char*pmtype,int created,int may_warn_about_nested_vars);
static Param assignnparam(char*s,mnumber val,int flags);
static void intsetfn(Param pm,zlong x);
static double floatgetfn(Param pm);
static void floatsetfn(Param pm,double x);
static void arrhashsetfn(Param pm,char**val,int flags);
static void simple_arrayuniq(char**x,int freeok);
static void arrayuniq_freenode(HashNode hn);
static void arrayuniq(char**x,int freeok);
static void clear_mbstate(void);
static void setlang(char*x);
static void argzerosetfn(UNUSED(Param pm),char*x);
static char*argzerogetfn(UNUSED(Param pm));
static char**pipestatgetfn(UNUSED(Param pm));
static void pipestatsetfn(UNUSED(Param pm),char**x);
#ifndef USE_SET_UNSET_ENV
static int findenv(char*name,int*pos);
#endif
static void copyenvstr(char*s,char*value,int flags);
static char*mkenvstr(char*name,char*value,int flags);
static void scanendscope(HashNode hn,UNUSED(int flags));
