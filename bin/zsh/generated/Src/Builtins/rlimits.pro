/* Generated automatically */
static void set_resinfo(void);
static void free_resinfo(void);
static int find_resource(char c);
static void printrlim(rlim_t val,const char*unit);
static rlim_t zstrtorlimt(const char*s,char**t,int base);
static void showlimitvalue(int lim,rlim_t val);
static int showlimits(char*nam,int hard,int lim);
static int printulimit(char*nam,int lim,int hard,int head);
static int do_limit(char*nam,int lim,rlim_t val,int hard,int soft,int set);
static int bin_limit(char*nam,char**argv,Options ops,UNUSED(int func));
static int do_unlimit(char*nam,int lim,int hard,int soft,int set,int euid);
static int bin_unlimit(char*nam,char**argv,Options ops,UNUSED(int func));
static int bin_ulimit(char*name,char**argv,UNUSED(Options ops),UNUSED(int func));
