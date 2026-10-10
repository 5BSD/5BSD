/* Generated automatically */
static void set_list_code(int p,int type,int cmplx);
static void set_sublist_code(int p,int type,int flags,int skip,int cmplx);
static void par_list(int*cmplx);
static void par_list1(int*cmplx);
static int par_sublist(int*cmplx);
static int par_sublist2(int*cmplx);
static int par_pline(int*cmplx);
static int par_cmd(int*cmplx,int zsh_construct);
static void par_for(int*cmplx);
static void par_case(int*cmplx);
static void par_if(int*cmplx);
static void par_while(int*cmplx);
static void par_repeat(int*cmplx);
static void par_subsh(int*cmplx,int zsh_construct);
static void par_funcdef(int*cmplx);
static void par_time(void);
static void par_dinbrack(void);
static int par_simple(int*cmplx,int nr);
static int par_redir(int*rp,char*idstring);
static int par_wordlist(void);
static int par_nl_wordlist(void);
static int par_cond(void);
static int par_cond_1(void);
static int par_cond_2(void);
static int par_cond_double(char*a,char*b);
static int get_cond_num(char*tst);
static int par_cond_triple(char*a,char*b,char*c);
static int par_cond_multi(char*a,LinkList l);
static void yyerror(int noerr);
static Wordcode load_dump_header(char*nam,char*name,int err);
static int build_dump(char*nam,char*dump,char**files,int ali,int map,int flags);
static int build_cur_dump(char*nam,char*dump,char**names,int match,int map,int what);
#if defined(HAVE_SYS_MMAN_H) && defined(HAVE_MMAP) && defined(HAVE_MUNMAP)
#if defined(MAP_SHARED) && defined(PROT_READ)
#define USE_MMAP 1
#endif
#endif
#ifdef USE_MMAP
static int zwcstat(char*filename,struct stat*buf);
#endif
static Eprog check_dump_file(char*file,struct stat*sbuf,char*name,int*ksh,int test_only);
