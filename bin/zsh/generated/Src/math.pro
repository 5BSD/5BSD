/* Generated automatically */
static int zzlex(void);
static void push(mnumber val,char*lval,int getme);
static mnumber pop(int noget);
static mnumber getcvar(char*s);
static mnumber setmathvar(struct mathvalue*mvp,mnumber v);
static mnumber callmathfunc(char*o);
static int notzero(mnumber a);
static void bop(int tk);
static void checkunary(int mtokc,char*mptr);
static void mathparse(int pc);
