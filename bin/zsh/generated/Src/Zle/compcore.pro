/* Generated automatically */
static void callcompfunc(char*s,char*fn);
static int makecomplist(char*s,int incmd,int lst);
static int matchcmp(Cmatch*a,Cmatch*b);
static int matcheq(Cmatch a,Cmatch b);
static Cmatch*makearray(LinkList l,int type,int flags,int*np,int*nlp,int*llp);
static Cmatch dupmatch(Cmatch m,int nbeg,int nend);
static void freematch(Cmatch m,int nbeg,int nend);
