/* Generated automatically */
static void statmodeprint(mode_t mode,char*outbuf,int flags);
static void statuidprint(uid_t uid,char*outbuf,int flags);
static void statgidprint(gid_t gid,char*outbuf,int flags);
static void stattimeprint(time_t tim,long nsecs,char*outbuf,int flags);
static void statulprint(unsigned long num,char*outbuf);
static void statlinkprint(struct stat*sbuf,char*outbuf,char*fname);
static void statprint(struct stat*sbuf,char*outbuf,char*fname,int iwhich,int flags);
static int bin_stat(char*name,char**args,Options ops,UNUSED(int func));
