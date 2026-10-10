/* Generated automatically */
static int addbuiltin(Builtin b);
static int add_autobin(const char*module,const char*bnam,int flags);
static int del_autobin(UNUSED(const char*module),const char*bnam,int flags);
static int setbuiltins(char const*nam,Builtin binl,int size,int*e);
static int addconddef(Conddef c);
static int setconddefs(char const*nam,Conddef c,int size,int*e);
static int add_autocond(const char*module,const char*cnam,int flags);
static int del_autocond(UNUSED(const char*modnam),const char*cnam,int flags);
static int setparamdefs(char const*nam,Paramdef d,int size,int*e);
static int add_autoparam(const char*module,const char*pnam,int flags);
static int del_autoparam(UNUSED(const char*modnam),const char*pnam,int flags);
static int addmathfunc(MathFunc f);
static int setmathfuncs(char const*nam,MathFunc f,int size,int*e);
static int add_automathfunc(const char*module,const char*fnam,int flags);
static int del_automathfunc(UNUSED(const char*modnam),const char*fnam,int flags);
#ifdef DYNAMIC
#ifdef AIXDYNAMIC
#else
#ifdef HPUX10DYNAMIC
#endif
#endif /* !AIXDYNAMIC */
static void*try_load_module(char const*name);
static void*do_load_module(char const*name,int silent);
#else /* !DYNAMIC */
static void*do_load_module(char const*name,int silent);
#endif /* !DYNAMIC */
static Module find_module(const char*name,int flags,const char**namep);
static void delete_module(Module m);
#ifdef DYNAMIC
#ifdef AIXDYNAMIC
static int dyn_setup_module(Module m);
static int dyn_features_module(Module m,char***features);
static int dyn_enables_module(Module m,int**enables);
static int dyn_boot_module(Module m);
static int dyn_cleanup_module(Module m);
static int dyn_finish_module(Module m);
#else
static int dyn_setup_module(Module m);
static int dyn_features_module(Module m,char***features);
static int dyn_enables_module(Module m,int**enables);
static int dyn_boot_module(Module m);
static int dyn_cleanup_module(Module m);
static int dyn_finish_module(Module m);
#endif /* !AIXDYNAMIC */
static int setup_module(Module m);
static int features_module(Module m,char***features);
static int enables_module(Module m,int**enables);
static int boot_module(Module m);
static int cleanup_module(Module m);
static int finish_module(Module m);
#else /* !DYNAMIC */
static int setup_module(Module m);
static int features_module(Module m,char***features);
static int enables_module(Module m,int**enables);
static int boot_module(Module m);
static int cleanup_module(Module m);
static int finish_module(Module m);
#endif /* !DYNAMIC */
static int do_module_features(Module m,Feature_enables enablesarr,int flags);
static int do_boot_module(Module m,Feature_enables enablesarr,int silent);
static int do_cleanup_module(Module m);
static int modname_ok(char const*p);
static void autoloadscan(HashNode hn,int printflags);
static int bin_zmodload_alias(char*nam,char**args,Options ops);
static int bin_zmodload_exist(UNUSED(char*nam),char**args,Options ops);
static int bin_zmodload_dep(UNUSED(char*nam),char**args,Options ops);
static int bin_zmodload_auto(char*nam,char**args,Options ops);
static int bin_zmodload_load(char*nam,char**args,Options ops);
static int bin_zmodload_features(const char*nam,char**args,Options ops);
