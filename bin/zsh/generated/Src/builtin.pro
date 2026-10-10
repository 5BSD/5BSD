/* Generated automatically */
static void printbuiltinnode(HashNode hn,int printflags);
static void freebuiltinnode(HashNode hn);
static int new_optarg(Options ops);
static LinkNode cd_get_dest(char*nam,char**argv,int hard,int func);
static char*cd_do_chdir(char*cnam,char*dest,int hard);
static char*cd_try_chdir(char*pfix,char*dest,int hard);
static void cd_new_pwd(int func,LinkNode dir,int quiet);
static void printdirstack(void);
static zlong fcgetcomm(char*s);
static int fcsubs(char**sp,struct asgment*sub);
static int fclist(FILE*f,Options ops,zlong first,zlong last,struct asgment*subs,Patprog pprog,int is_command);
static int fcedit(char*ename,char*fn);
static Asgment getasg(char***argvp,LinkList assigns);
static Param typeset_single(char*cname,char*pname,Param pm,int func,int on,int off,int roff,Asgment asg,Param altpm,Options ops,int joinchar);
static int check_autoload(Shfunc shf,char*name,Options ops,int func);
static void checkjobs(void);
static int zread(int izle,int*readchar,long izle_timeout);
