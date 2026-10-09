/* Generated automatically */
static int getposint(char*instr,char*nam);
static int bin_sysread(char*nam,char**args,Options ops,UNUSED(int func));
static int bin_syswrite(char*nam,char**args,Options ops,UNUSED(int func));
static int bin_sysopen(char*nam,char**args,Options ops,UNUSED(int func));
static int bin_sysseek(char*nam,char**args,Options ops,UNUSED(int func));
static mnumber math_systell(UNUSED(char*name),UNUSED(int argc),mnumber*argv,UNUSED(int id));
static int bin_syserror(char*nam,char**args,Options ops,UNUSED(int func));
static int bin_zsystem_flock(char*nam,char**args,UNUSED(Options ops),UNUSED(int func));
static int bin_zsystem_supports(char*nam,char**args,UNUSED(Options ops),UNUSED(int func));
static int bin_zsystem(char*nam,char**args,Options ops,int func);
static char**errnosgetfn(UNUSED(Param pm));
static void fillpmsysparams(Param pm,const char*name);
static HashNode getpmsysparams(UNUSED(HashTable ht),const char*name);
static void scanpmsysparams(UNUSED(HashTable ht),ScanFunc func,int flags);
