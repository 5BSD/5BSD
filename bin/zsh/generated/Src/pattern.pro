/* Generated automatically */
static void patadd(char*add,int ch,long n,int paflags);
static long patcompswitch(int paren,int*flagp);
static long patcompbranch(int*flagp,int paren);
static long patcomppiece(int*flagp,int paren);
static long patcompnot(int paren,int*flagsp);
static long patnode(long op);
static void patinsert(long op,int opnd,char*xtra,int sz);
static void pattail(long p,long val);
static void patoptail(long p,long val);
static void patmungestring(char**string,int*stringlen,int*unmetalenin);
static int patmatch(Upat prog);
#ifdef MULTIBYTE_SUPPORT
#endif /* MULTIBYTE_SUPPORT */
#ifndef MULTIBYTE_SUPPORT
#endif /* MULTIBYTE_SUPPORT */
static int patrepeat(Upat p,char*charstart);
