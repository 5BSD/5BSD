/* Generated automatically */
static int cpatterns_same(Cpattern a,Cpattern b);
static int cmatchers_same(Cmatcher a,Cmatcher b);
static void start_match(void);
static void abort_match(void);
static void add_match_str(Cmatcher m,char*l,char*w,int wl,int sfx);
static void add_match_part(Cmatcher m,char*l,char*w,int wl,char*o,int ol,char*s,int sl,int osl,int sfx);
static void add_match_sub(Cmatcher m,char*l,int ll,char*w,int wl);
static int match_parts(char*l,char*w,int n,int part);
static int pattern_match_restrict(Cpattern p,Cpattern wp,convchar_t*wsc,int wsclen,Cpattern prestrict,ZLE_STRING_T new_line);
static int bld_line(Cmatcher mp,ZLE_STRING_T line,char*mword,char*word,int wlen,int sfx);
static char*join_strs(int la,char*sa,int lb,char*sb);
static int cmp_anchors(Cline o,Cline n,int join);
static void join_psfx(Cline ot,Cline nt,Cline*orest,Cline*nrest,int sfx);
static void join_mid(Cline o,Cline n);
static int sub_join(Cline a,Cline b,Cline e,int anew);
