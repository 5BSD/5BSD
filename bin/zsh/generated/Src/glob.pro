/* Generated automatically */
static void addpath(char*s,int l);
static void insert(char*s,int checked);
static void scanner(Complist q,int shortcircuit);
static Complist parsecomplist(char*instr);
static Complist parsepat(char*str);
static off_t qgetnum(char**s);
static zlong qgetmodespec(char**s);
static char*glob_exec_string(char**sp);
static int bracechardots(char*str,convchar_t*c1p,convchar_t*c2p);
static char*get_match_ret(Imatchdata imd,int b,int e);
static void set_pat_start(Patprog p,int offs);
static void set_pat_end(Patprog p,char null_me);
#ifdef MULTIBYTE_SUPPORT
static int iincchar(char**tp,int left);
static int igetmatch(char**sp,Patprog p,int fl,int n,char*replstr,LinkList*repllistp);
#else
static int igetmatch(char**sp,Patprog p,int fl,int n,char*replstr,LinkList*repllistp);
#endif /* MULTIBYTE_SUPPORT */
static void zshtokenize(char*s,int flags);
static int qualdev(UNUSED(char*name),struct stat*buf,off_t dv,UNUSED(char*dummy));
static int qualnlink(UNUSED(char*name),struct stat*buf,off_t ct,UNUSED(char*dummy));
static int qualuid(UNUSED(char*name),struct stat*buf,off_t uid,UNUSED(char*dummy));
static int qualgid(UNUSED(char*name),struct stat*buf,off_t gid,UNUSED(char*dummy));
static int qualisdev(UNUSED(char*name),struct stat*buf,UNUSED(off_t junk),UNUSED(char*dummy));
static int qualisblk(UNUSED(char*name),struct stat*buf,UNUSED(off_t junk),UNUSED(char*dummy));
static int qualischr(UNUSED(char*name),struct stat*buf,UNUSED(off_t junk),UNUSED(char*dummy));
static int qualisdir(UNUSED(char*name),struct stat*buf,UNUSED(off_t junk),UNUSED(char*dummy));
static int qualisfifo(UNUSED(char*name),struct stat*buf,UNUSED(off_t junk),UNUSED(char*dummy));
static int qualislnk(UNUSED(char*name),struct stat*buf,UNUSED(off_t junk),UNUSED(char*dummy));
static int qualisreg(UNUSED(char*name),struct stat*buf,UNUSED(off_t junk),UNUSED(char*dummy));
static int qualissock(UNUSED(char*name),struct stat*buf,UNUSED(off_t junk),UNUSED(char*dummy));
static int qualflags(UNUSED(char*name),struct stat*buf,off_t mod,UNUSED(char*dummy));
static int qualmodeflags(UNUSED(char*name),struct stat*buf,off_t mod,UNUSED(char*dummy));
static int qualiscom(UNUSED(char*name),struct stat*buf,UNUSED(off_t mod),UNUSED(char*dummy));
static int qualsize(UNUSED(char*name),struct stat*buf,off_t size,UNUSED(char*dummy));
static int qualtime(UNUSED(char*name),struct stat*buf,off_t days,UNUSED(char*dummy));
static int qualsheval(char*name,UNUSED(struct stat*buf),UNUSED(off_t days),char*str);
static int qualnonemptydir(char*name,struct stat*buf,UNUSED(off_t days),UNUSED(char*str));
