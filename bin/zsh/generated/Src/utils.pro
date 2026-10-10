/* Generated automatically */
#ifdef MULTIBYTE_SUPPORT
#endif /* MULTIBYTE_SUPPORT */
static char**slashsplit(char*s);
static int xsymlinks(char*s);
static void finddir_scan(HashNode hn,UNUSED(int flags));
static int dircmp(char*s,char*t);
static void checkmailpath(char**s);
static void spscan(HashNode hn,UNUSED(int scanflags));
static int skipwsep(char**s);
static int findsep(char**s,char*sep,int quote);
#ifdef MULTIBYTE_SUPPORT
#endif
#ifdef MULTIBYTE_SUPPORT
#endif /* MULTIBYTE_SUPPORT */
static char*spname(char*oldname);
static int mindist(char*dir,char*mindistguess,char*mindistbest,int wantdir);
static int spdist(char*s,char*t,int thresh);
#ifndef MULTIBYTE_SUPPORT
#endif
#ifdef MULTIBYTE_SUPPORT
#else /* MULTIBYTE_SUPPORT */
#endif /* MULTIBYTE_SUPPORT */
static int upchdir(int n);
#ifdef MAILDIR_SUPPORT
#endif
