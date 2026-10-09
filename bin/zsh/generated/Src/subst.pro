/* Generated automatically */
static LinkNode keyvalpairelement(LinkList list,LinkNode node);
static char*stringsubstquote(char*strstart,char**pstrdpos);
static LinkNode stringsubst(LinkList list,LinkNode node,int pf_flags,int*ret_flags,int asssub);
static int multsub(char**s,int pf_flags,char***a,int*isarr,char*sep,int*ms_flags);
static char*strcatsub(char**d,char*pb,char*pe,char*src,int l,char*s,int glbsub,int copied);
static int get_intarg(char**s,int*delmatchp);
static LinkNode paramsubst(LinkList l,LinkNode n,char**str,int qt,int pf_flags,int*ret_flags);
static char*arithsubst(char*a,char**bptr,char*rest);
static char*dstackent(char ch,int val);
