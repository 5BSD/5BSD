/* SPDX-License-Identifier: BSD-2-Clause */
/* Native orchestration; backend commands are argv vectors, never shell text. */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sha256.h>
#include <sha512.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SOURCE "/usr/src"
#define OBJECT "/usr/obj"
#define REPOSITORY "/usr/obj/usr/src/repo"
#define RUNS "/usr/obj/usr/src/build-runs"
#define HELPERS SOURCE "/tools/build/capimage/"
#define PYTHON "/usr/local/bin/python3.12"
#define MAX_STEPS 40
#define MAX_ARGS 80
struct option { const char *name, *initial; char *value; bool boolean, selected; };
static struct option options[] = {
#define S(n,d) {n,d,NULL,false,false}
#define B(n) {n,"no",NULL,true,false}
 S("arch","native"), S("board","generic"), S("jobs","auto"),
 S("kernel","GENERIC"), S("kernel-dir",""), S("src-conf","/etc/src.conf"),
 S("make-conf","/etc/make.conf"), S("build-profile","auto"),
 S("signing","auto"), S("key",""),
 S("development-key","/usr/obj/usr/src/signing-keys/development.pem"),
 S("pkg-key",""), S("public-key",""), S("pkg-public-key",""),
 S("root",""), S("output",""), S("repository",""),
 S("publish-repository",REPOSITORY), S("ports","/usr/obj/5BSD-ports"),
 S("hardware-profile",""), S("distfiles",""),
 S("bootenv",""), S("clone-from",""), S("be-root",""), S("media-format","all"),
 S("format","text"), S("build-backend","bsd-make"),
 B("incremental"),
 B("relaxed-signatures"), B("allow-debug-publication"), B("production")
#undef S
#undef B
};
struct step { char *name, *argv[MAX_ARGS]; size_t argc; bool terminal; };
struct request {
 const char *action, *target, *arch;
 char *run, *native;
 unsigned jobs;
 bool plan, json, packages, cross, production;
 struct step steps[MAX_STEPS]; size_t count;
};
static struct request request;
static volatile sig_atomic_t interrupted;
static volatile sig_atomic_t child_pid;
static char *format(const char *fmt, ...) __printflike(1,2);
static char *
format(const char *fmt, ...)
{
 char *s; va_list ap; va_start(ap,fmt);
 if (vasprintf(&s,fmt,ap)<0) err(1,"allocation");
 va_end(ap); return s;
}
static void
fail(const char *message) { errx(1,"%s",message); }
static struct option *
lookup(const char *name)
{
 for (size_t i=0;i<nitems(options);i++) if (!strcmp(name,options[i].name)) return &options[i];
 return NULL;
}
static const char *get(const char *n) { return lookup(n)->value; }
static bool yes(const char *n) { return !strcmp(get(n),"yes"); }
static bool selected(const char *n) { return lookup(n)->selected; }
static bool action(const char *n) { return !strcmp(request.action,n); }
static void
set(const char *n,const char *v,bool explicit)
{
 struct option *o=lookup(n);
 if (!o) errx(64,"unknown option: %s",n);
 if (!*v && explicit) errx(64,"empty option: %s",n);
 for (const unsigned char *p=(const unsigned char *)v;*p;p++)
  if (iscntrl(*p)) fail("control characters in option");
 if (o->boolean && strcmp(v,"yes") && strcmp(v,"no")) errx(64,"%s must be yes or no",n);
 free(o->value);o->value=strdup(v);if (!o->value) err(1,"strdup");
 o->selected|=explicit;
 if (explicit && !strcmp(n,"production")) set("build-profile",!strcmp(v,"yes")?"production":"development",explicit);
}
static bool
oneof(const char *s,const char *values)
{
 char *copy=strdup(values),*p=copy,*word;bool found=false;
 if (!copy) err(1,"strdup");
 while ((word=strsep(&p,"|"))!=NULL) if (!strcmp(s,word)) found=true;
 free(copy);return found;
}
static bool
under(const char *p,const char *base)
{
 size_t n=strlen(base);return !strncmp(p,base,n) && (p[n]=='/' || p[n]=='\0');
}
static void
regular(const char *p, bool secret)
{
 struct stat st;int fd=open(p,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
 if (fd<0 || fstat(fd,&st)<0 || !S_ISREG(st.st_mode)) errx(1,"requires a readable regular file, not a symlink (not readable or unsafe): %s",p);
 close(fd);
 if (secret && (st.st_mode&077)) fail("private key must not be accessible to group or others");
}
/* Resolve existing ancestors without creating anything. */
static char *
future(const char *p)
{
 char physical[PATH_MAX], *probe, *suffix=strdup("");struct stat st;
 if (*p!='/') fail("path must be absolute");
 if (strstr(p,"/../") || strstr(p,"/./") ||
     (strlen(p)>=3 && !strcmp(p+strlen(p)-3,"/..")) ||
     (strlen(p)>=2 && !strcmp(p+strlen(p)-2,"/."))) fail("path must not contain traversal");
 probe=strdup(p);if (!probe || !suffix) err(1,"strdup");
 while (lstat(probe,&st)<0) {
  if (errno!=ENOENT) err(1,"path %s",probe);
  char *slash=strrchr(probe,'/'),*next;
  if (!slash || !slash[1]) fail("invalid path");
  next=format("/%s%s",slash+1,suffix);free(suffix);suffix=next;
  if (slash==probe) slash[1]='\0';else *slash='\0';
 }
 if (!realpath(probe,physical)) err(1,"realpath %s",probe);
 char *result=format("%s%s",!strcmp(physical,"/")?"":physical,suffix);
 free(probe);free(suffix);return *result?result:strdup("/");
}
static void
canonical(const char *n) { char *p=future(get(n));set(n,p,false);free(p); }
static void
key_parent(const char *key)
{
 char *p=strdup(key),*slash=strrchr(p,'/');struct stat st;
 if (!slash) fail("key path must be absolute");
 if (slash==p) slash[1]='\0';else *slash='\0';
 if (stat(p,&st)==0 && (st.st_mode&022)) fail("private key directory must not be writable by group or others");
 free(p);
}
static void
config(const char *path)
{
 char *line=NULL;size_t cap=0,number=0;ssize_t n;
 bool seen[nitems(options)];memset(seen,0,sizeof(seen));regular(path,false);
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)err(1,"config");
 FILE *fp=fdopen(fd,"r");if(!fp)err(1,"config");
 while ((n=getline(&line,&cap,fp))>=0) {
  number++;if(n>16384)fail("config record too long");
  if(n && line[n-1]=='\n')line[--n]='\0';
  if ((size_t)n!=strlen(line)) fail("NUL in config");
  if(!n || line[0]=='#')continue;
  char *v=strchr(line,'=');if(!v)errx(64,"expected key=value at line %zu",number);*v++='\0';
  for(char *p=line;*p;p++)if(*p=='_')*p='-';
  struct option *o=lookup(line);if(!o)errx(64,"unknown config setting: %s",line);
  size_t i=(size_t)(o-options);if(seen[i])errx(64,"duplicate config setting: %s",line);seen[i]=true;
  set(line,v,true);
 }
 if(ferror(fp))err(1,"read config");free(line);fclose(fp);
}
static void
usage_status(int code)
{
 FILE *out = code == 0 ? stdout : stderr;
 fprintf(out, "usage: build-bsd [plan] build|world|kernel|stage|packages|sign|verify|deploy|bsdinstall|media [options]\n"
     "       build-bsd status run-directory\n"
     "       build-bsd --help\n\n"
     "Options (boolean flags accept yes/no in configuration files):\n"
     "  --config FILE  Literal configuration; command-line options override it\n");
 for (size_t i = 0; i < nitems(options); i++) {
  const struct option *o = &options[i];
  fprintf(out, "  --%s%s", o->name, o->boolean ? "" : " VALUE");
  if (*o->initial) fprintf(out, " (default: %s)", o->initial);
  fputc('\n', out);
 }
 fprintf(out, "\nSee build-bsd(8) for allowed values and action-specific options.\n");
 exit(code);
}
static void
usage(void)
{
 usage_status(64);
}
static void
parse(int argc,char **argv)
{
 const char *conf=NULL;int start=1;
 for(size_t i=0;i<nitems(options);i++)set(options[i].name,options[i].initial,false);
 if(getenv("PORTSDIR") && *getenv("PORTSDIR"))set("ports",getenv("PORTSDIR"),false);
 if(getenv("KERNCONF") && *getenv("KERNCONF"))set("kernel",getenv("KERNCONF"),true);
 if(argc>1 && !strcmp(argv[1],"plan")){request.plan=true;start++;}
 if(argc<=start)usage();request.action=argv[start++];
 if(!oneof(request.action,"build|world|kernel|stage|packages|sign|verify|deploy|bsdinstall|media"))usage();
 for(int i=start;i<argc;i++) {
  if(!strcmp(argv[i],"--config")) { if(++i==argc)usage();if(conf)fail("only one --config is allowed");conf=argv[i];continue; }
  if(strncmp(argv[i],"--",2))usage();struct option *o=lookup(argv[i]+2);if(!o)usage();
  if(!o->boolean && ++i==argc)usage();
 }
 if(conf)config(conf);
 for(int i=start;i<argc;i++) {
  if(!strcmp(argv[i],"--config")){i++;continue;}
  struct option *o=lookup(argv[i]+2);set(o->name,o->boolean?"yes":argv[++i],true);
 }
 if(action("build"))request.action="packages";
 request.packages=action("packages");request.json=!strcmp(get("format"),"json");
 if(!oneof(get("format"),"text|json"))fail("--format must be text or json");
 if(request.json && !request.plan)fail("--format json requires plan");
}
static void
validate(void)
{
 char host[64];size_t len=sizeof(host);struct stat st;
 if(sysctlbyname("hw.machine_arch",host,&len,NULL,0)<0)err(1,"host architecture");
 bool native_arch=!strcmp(get("arch"),"native");
 if(native_arch)set("arch",host,false);
 if(!oneof(get("board"),"generic|rpi4|rpi5|rpi-zero2w"))fail("--board must be generic, rpi4, rpi5 or rpi-zero2w");
 if(strcmp(get("board"),"generic")) {
  if(selected("arch") && !native_arch && !oneof(get("arch"),"arm64|aarch64"))fail("Raspberry Pi board profiles require arm64");
  set("arch","arm64",false);
  if(!selected("kernel"))set("kernel",!strcmp(get("board"),"rpi5")?"GENERIC":"GENERIC-RPI",false);
  if(!request.packages && !action("stage"))fail("board image backend is not integrated; board applies to stage/build/packages");
 }
 if(!strcmp(get("arch"),"amd64")){request.target="amd64";request.arch="amd64";}
 else if(oneof(get("arch"),"arm64|aarch64")){request.target="arm64";request.arch="aarch64";}
 else if(oneof(get("arch"),"riscv|riscv64")){request.target="riscv";request.arch="riscv64";}
 else fail("--arch must be native, amd64, arm64, or riscv64");
 request.cross=strcmp(host,request.arch)!=0;
 if(!strcmp(get("jobs"),"auto")){int cpus;len=sizeof(cpus);if(sysctlbyname("hw.ncpu",&cpus,&len,NULL,0)<0)err(1,"CPUs");request.jobs=cpus;}
 else {char *end;errno=0;unsigned long j=strtoul(get("jobs"),&end,10);if(strspn(get("jobs"),"0123456789")!=strlen(get("jobs")) || errno || *end || !j || j>104857 || strlen(get("jobs"))>6)fail("--jobs must be a positive integer or auto");request.jobs=j;}
 if(!strcmp(get("build-profile"),"auto"))set("build-profile",request.packages?"production":"development",false);
 if(!oneof(get("build-profile"),"production|development|debug"))fail("--build-profile must be production, development or debug");
 request.production=!strcmp(get("build-profile"),"production");
 if(request.packages && !request.production && !yes("allow-debug-publication"))fail("development/debug publication requires --allow-debug-publication");
 if(yes("allow-debug-publication") && (!request.packages || request.production))fail("--allow-debug-publication requires development/debug packages");
 if(strcmp(get("build-backend"),"bsd-make"))fail("unknown build backend");
 if(!*get("kernel") || strspn(get("kernel"),"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")!=strlen(get("kernel")))fail("kernel must be a configuration name");
 const char *paths[]={"src-conf","make-conf"};
 for(size_t i=0;i<nitems(paths);i++) {if(*get(paths[i])!='/' || strchr(get(paths[i]),'$'))fail("world configuration paths must be absolute without make expansion");if(selected(paths[i]) && strcmp(get(paths[i]),"/dev/null"))regular(get(paths[i]),false);}
 if(*get("kernel-dir")){canonical("kernel-dir");regular(format("%s/%s",get("kernel-dir"),get("kernel")),false);}
 if(*get("pkg-key") && !request.packages)fail("--pkg-key applies only to build or packages");
 if(selected("ports") && !request.packages)fail("--ports applies only to packages");
 if(selected("publish-repository") && !request.packages)fail("--publish-repository applies only to packages/build");
 if(!strcmp(get("signing"),"auto"))set("signing",*get("key")?"signed":"unsigned",false);
 if(!oneof(get("signing"),"unsigned|development|signed"))fail("unknown signing mode");
 if(!strcmp(get("signing"),"signed")){regular(get("key"),true);canonical("key");key_parent(get("key"));}
 else if(*get("key"))fail("--key requires signed mode");
 if(selected("development-key") && strcmp(get("signing"),"development"))fail("--development-key requires development signing");
 if(lstat(get("development-key"),&st)==0)regular(get("development-key"),true);
 canonical("development-key");key_parent(get("development-key"));
 if(lstat(get("development-key"),&st)==0)regular(get("development-key"),true);
 if(*get("pkg-key")){regular(get("pkg-key"),true);canonical("pkg-key");key_parent(get("pkg-key"));}
 if(*get("publish-repository")!='/')fail("publication destination must be absolute");
 canonical("publish-repository");
 if(!strcmp(get("publish-repository"),"/") || under(get("publish-repository"),SOURCE) || under(get("publish-repository"),"/home") || !strcmp(get("publish-repository"),"/usr"))fail("publication destination must be separate from source and home directories");
 const char *keys[]={"key","development-key","pkg-key"};
 for(size_t i=0;i<nitems(keys);i++)if(*get(keys[i]) && under(get(keys[i]),get("publish-repository")))fail("private keys must be outside the publication destination");
 if(!strcmp(get("signing"),"unsigned") && yes("relaxed-signatures"))fail("relaxed signatures require signing");
 if(request.packages){
  if(request.cross)fail("native hardware backend cannot publish a foreign target");
  if(*get("output"))fail("packages uses maintained package staging directories");
  if(!*get("hardware-profile"))set("hardware-profile",format(SOURCE "/release/tools/hardware-ports.%s",request.arch),false);
  if(access(get("hardware-profile"),R_OK)<0)fail("native hardware backend requires a readable hardware profile");
  regular(get("hardware-profile"),false);canonical("hardware-profile");if(access(format("%s/Mk/bsd.port.mk",get("ports")),R_OK)<0)fail("ports checkout is missing");regular(format("%s/Mk/bsd.port.mk",get("ports")),false);canonical("ports");
  if(!*get("distfiles"))set("distfiles",format("%s/distfiles",get("ports")),false);canonical("distfiles");
 } else if(*get("hardware-profile") || *get("distfiles"))fail("hardware profile and distfiles apply only to build or packages");
 if(selected("media-format") && !action("media"))fail("--media-format applies only to media");
 if(!oneof(get("media-format"),"all|iso|memstick"))fail("invalid media format");
 bool deploy=action("deploy") || action("bsdinstall") || action("media");
 if(deploy){
  regular(get("public-key"),false);canonical("public-key");regular(get("pkg-public-key"),false);canonical("pkg-public-key");canonical("repository");regular(format("%s/publication.json",get("repository")),false);
  if(action("deploy")){if(!*get("root")==!*get("bootenv"))fail("deploy requires exactly one of --root or --bootenv");}
  else if(*get("root") || *get("bootenv") || *get("clone-from") || *get("be-root"))fail("--root/--bootenv/--clone-from apply only to deploy");
  if(*get("bootenv") && (strlen(get("bootenv"))>63 || !isalnum((unsigned char)*get("bootenv")) || strspn(get("bootenv"),"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")!=strlen(get("bootenv"))))fail("invalid boot environment name");
  if((*get("clone-from") || *get("be-root")) && !*get("bootenv"))fail("--clone-from/--be-root require --bootenv");
  if(*get("be-root") && !*get("clone-from"))fail("--be-root requires --clone-from");
  if(action("bsdinstall") && request.cross)fail("bsdinstall requires native architecture");
 } else if(*get("repository") || *get("pkg-public-key") || *get("bootenv") || *get("clone-from") || *get("be-root"))fail("repository settings apply only to deployment");
 if(action("verify") || action("sign")){
  if(!*get("root"))fail("requires --root DIRECTORY");canonical("root");
  if(!strcmp(get("root"),"/") || stat(get("root"),&st)<0 || !S_ISDIR(st.st_mode))fail("requires an alternate root directory");
  if(action("verify")){regular(get("public-key"),false);canonical("public-key");}
  if(action("sign") && strcmp(get("signing"),"signed"))fail("sign requires signed mode and --key");
 } else if(!deploy && (*get("root") || *get("public-key")))fail("--root and --public-key apply only to verify/sign/deploy");
 if(*get("output") && !action("stage") && !action("media"))fail("--output applies only to stage or media");
 if(action("stage") || action("media")){
  if(!*get("output"))set("output",format(OBJECT "/usr/src/%s/%s",action("media")?"media":"stages",strrchr(request.run,'/')+1),false);
  if(strpbrk(get("output")," \t") || strstr(get("output"),"/../"))fail("stage path must contain no traversal or whitespace");
  if(!under(get("output"),OBJECT) || !strcmp(get("output"),OBJECT))fail("staging must be under /usr/obj");
  if(lstat(get("output"),&st)==0 || errno!=ENOENT)fail("output stage must be a new path");canonical("output");
  if(!under(get("output"),OBJECT))fail("stage parent resolves outside /usr/obj");
  for(size_t i=0;i<nitems(keys);i++)if(*get(keys[i]) && under(get(keys[i]),get("output")))fail("private keys must be outside the stage");
 }
}
static struct step *
step(const char *name)
{
 if(request.count==MAX_STEPS)fail("too many backend steps");
 struct step *s=&request.steps[request.count++];s->name=strdup(name);return s;
}
static void
arg(struct step *s,const char *a)
{
 if(s->argc+1>=MAX_ARGS)fail("too many backend arguments");
 s->argv[s->argc++]=strdup(a);s->argv[s->argc]=NULL;
}
static void
args(struct step *s,...)
{
 va_list ap;const char *a;va_start(ap,s);
 while((a=va_arg(ap,const char *))!=NULL)arg(s,a);
 va_end(ap);
}
static void
assignment(struct step *s,const char *n,const char *v) { arg(s,format("%s=%s",n,v)); }
/* Backend interface: only this adapter knows BSD make variable names. */
static struct step *
bsd_make(const char *name,bool signing)
{
 struct step *s=step(name);
 args(s,"env","MAKEOBJDIRPREFIX=" OBJECT,"make","-C",SOURCE,"-j",format("%u",request.jobs),NULL);
 assignment(s,"TARGET",request.target);assignment(s,"TARGET_ARCH",request.arch);
 assignment(s,"KERNCONF",get("kernel"));assignment(s,"SRCCONF",get("src-conf"));assignment(s,"__MAKE_CONF",get("make-conf"));
 if(*get("kernel-dir"))assignment(s,"KERNCONFDIR",get("kernel-dir"));
 if(!strcmp(get("build-profile"),"debug"))arg(s,"DEBUG_FLAGS=-g");
 if(yes("allow-debug-publication"))arg(s,"ALLOW_DEBUG_MALLOC=yes");
 arg(s,request.production?"WITH_MALLOC_PRODUCTION=yes":"WITHOUT_MALLOC_PRODUCTION=yes");
 if(signing){
  assignment(s,"CAPIMAGE_SIGNING_MODE",get("signing"));assignment(s,"CAPIMAGE_SIGNING_KEY",get("key"));
  assignment(s,"CAPIMAGE_DEVELOPMENT_KEY",get("development-key"));assignment(s,"CAPIMAGE_REQUIRE_SIGNATURES",yes("relaxed-signatures")?"no":"");
  assignment(s,"CAPSIGN_HOST",format("%s/capsign",request.native));
 }
 return s;
}
struct build_backend { const char *name; struct step *(*make)(const char *,bool); };
static const struct build_backend backend={"bsd-make",bsd_make};
static void
plan(void)
{
 struct step *s;
 bool tools=action("verify") || action("sign") || action("deploy") || action("bsdinstall") || action("media") || strcmp(get("signing"),"unsigned");
 if(tools){
  s=step("host-tools-directory");args(s,"mkdir","-p",request.native,NULL);
  s=step("host-tools");args(s,"make","-C",request.native,"-f",HELPERS "host-tools.mk","-j",format("%u",request.jobs),"SRCTOP=" SOURCE,NULL);
 }
 if(action("verify") || action("sign")){
  s=step(request.action);args(s,"env",format("CAPSIGN=%s/capsign",request.native),"sh",action("sign")?HELPERS "sign-stage.sh":HELPERS "verify-stage.sh","-r",get("root"),action("sign")?"-k":"-p",action("sign")?get("key"):get("public-key"),NULL);
  if(action("sign") && !yes("relaxed-signatures"))arg(s,"-e");
  return;
 }
 if(action("deploy") || action("bsdinstall")){
  s=step(request.action);args(s,PYTHON,action("deploy")?HELPERS "deploy.py":HELPERS "installer.py","--repository",get("repository"),"--pkg-public-key",get("pkg-public-key"),"--public-key",get("public-key"),"--kernel",get("kernel"),"--capsign",format("%s/capsign",request.native),NULL);
  if(action("deploy")){
   args(s,*get("bootenv")?"--bootenv":"--root",*get("bootenv")?get("bootenv"):get("root"),NULL);
   if(*get("clone-from"))args(s,"--clone-from",get("clone-from"),NULL);
   if(*get("be-root"))args(s,"--be-root",get("be-root"),NULL);
  } else s->terminal=true;
  return;
 }
 if(action("media")){
  s=step("media-code-key");args(s,format("%s/capsign",request.native),"key-id","-p",get("public-key"),NULL);
  s=step("media-directory");args(s,"mkdir","-p",get("output"),NULL);
  s=step("media");args(s,"env","MAKEOBJDIRPREFIX=" OBJECT,"make","-C",SOURCE "/release","-j",format("%u",request.jobs),NULL);
  assignment(s,"RELEASE_OBJDIR",get("output"));assignment(s,"TARGET",request.target);assignment(s,"TARGET_ARCH",request.arch);assignment(s,"KERNCONF",get("kernel"));assignment(s,"SRCCONF",get("src-conf"));assignment(s,"__MAKE_CONF",get("make-conf"));assignment(s,"PORTSDIR",get("ports"));assignment(s,"PKGBASE_SIGNED_REPOSITORY",get("repository"));assignment(s,"PKGBASE_REPO_PUBLIC_KEY",get("pkg-public-key"));assignment(s,"PKGBASE_CODE_PUBLIC_KEY",get("public-key"));args(s,"HARDWARE_PYTHON=" PYTHON,"NOPKGBASE=","NODISTSETS=yes","NOPKG=yes",NULL);
  if(*get("kernel-dir"))assignment(s,"KERNCONFDIR",get("kernel-dir"));
  if(strcmp(get("media-format"),"memstick"))arg(s,"disc1.iso");if(strcmp(get("media-format"),"iso"))arg(s,"memstick.img");return;
 }
 if(!action("kernel")){s=backend.make("buildworld",false);arg(s,yes("incremental")?"WITHOUT_CLEAN=yes":"WITH_CLEAN=yes");arg(s,"buildworld");}
 if(!action("world")){s=backend.make("buildkernel",false);arg(s,yes("incremental")?"WITHOUT_CLEAN=yes":"WITH_CLEAN=yes");arg(s,"buildkernel");}
 if(action("stage")){
  char *parent=strdup(get("output"));*strrchr(parent,'/')='\0';
  s=step("stage-parent");args(s,"mkdir","-p",parent,NULL);free(parent);
  s=step("stage-directory");args(s,"mkdir",get("output"),NULL);
  const char *targets[]={"installworld","distribution","installkernel","capimage-stage"};
  for(size_t i=0;i<nitems(targets);i++){
   s=backend.make(targets[i],i==3);arg(s,"NO_ROOT=yes");assignment(s,"DESTDIR",get("output"));arg(s,targets[i]);
  }
 } else if(request.packages){
  s=backend.make("system-packages",true);assignment(s,"PORTSDIR",get("ports"));assignment(s,"HARDWARE_PORT_LIST",get("hardware-profile"));assignment(s,"DISTDIR",get("distfiles"));arg(s,"REPODIR=" REPOSITORY);assignment(s,"PUBLISH_REPODIR",get("publish-repository"));
  if(*get("pkg-key")){assignment(s,"PKG_REPO_SIGNING_KEY",get("pkg-key"));assignment(s,"HARDWARE_SIGNING_KEY",get("pkg-key"));}
  arg(s,"system-packages");
 }
}
static void
json_string(const char *s)
{
 putchar('"');for(const unsigned char *p=(const unsigned char *)s;*p;p++){
  if(*p=='"' || *p=='\\')printf("\\%c",*p);else if(*p<32 || *p>=127)printf("\\u%04x",*p);else putchar(*p);
 }putchar('"');
}
static void
show_request(void)
{
 if(!request.json){printf("build-bsd: action=%s cpus=%u kernel=%s production=%s signing=%s target=%s/%s board=%s\n",request.action,request.jobs,get("kernel"),request.production?"yes":"no",get("signing"),request.target,request.arch,get("board"));return;}
 printf("{\"schema\":\"org.5bsd.build-plan.v1\",\"record\":\"request\",\"action\":");json_string(request.action);
 const char *names[]={"target","target_arch","kernel","board","build_profile","signing","build_backend","hardware_backend"};
 const char *values[]={request.target,request.arch,get("kernel"),get("board"),get("build-profile"),get("signing"),backend.name,"native-ports"};
 for(size_t i=0;i<nitems(names);i++){printf(",\"%s\":",names[i]);json_string(values[i]);}printf(",\"jobs\":%u}\n",request.jobs);
}
static void
show_step(struct step *s,size_t number)
{
 if(request.json){printf("{\"schema\":\"org.5bsd.build-plan.v1\",\"record\":\"step\",\"number\":%zu,\"name\":",number);json_string(s->name);printf(",\"argv\":[");for(size_t i=0;i<s->argc;i++){if(i)putchar(',');json_string(s->argv[i]);}puts("]}");}
 else {printf("%s:",s->name);for(size_t i=0;i<s->argc;i++)printf(" %s",s->argv[i]);putchar('\n');}
 fflush(stdout);
}
static void
mkdirs(const char *path)
{
 char *copy=strdup(path);struct stat st;if(!copy)err(1,"strdup");
 for(char *p=copy+1;;p++)if(*p=='/' || *p=='\0'){
  char c=*p;*p='\0';if(mkdir(copy,0700)<0 && errno!=EEXIST)err(1,"mkdir %s",copy);
  if(lstat(copy,&st)<0 || !S_ISDIR(st.st_mode))errx(1,"unsafe directory: %s",copy);
  *p=c;if(!c)break;
 }
 free(copy);
}
static void
status(const char *state,const char *name,int code)
{
 char *path=format("%s/status",request.run),*tmp=format("%s/status.new",request.run);
 int fd=open(tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)err(1,"status");
 if(!strcmp(state,"complete"))dprintf(fd,"complete action=%s logs=%s %s=%s\n",request.action,request.run,action("media")?"output":"stage",get("output"));
 else dprintf(fd,"%s step=%s exit=%d logs=%s\n",state,name,code,request.run);
 if(fsync(fd)<0 || close(fd)<0 || rename(tmp,path)<0)err(1,"status update");free(path);free(tmp);
}
static void
signal_handler(int sig)
{
 interrupted=sig;if(child_pid>0)kill(-(pid_t)child_pid,sig);
}
static int
execute(struct step *s,size_t number)
{
 int pipefd[2]={-1,-1},log=-1,wstatus;pid_t pid;
 if(!s->terminal){
  log=open(format("%s/%02zu-%s.log",request.run,number,s->name),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(log<0 || pipe2(pipefd,O_CLOEXEC)<0)err(1,"step logging");
 }
 pid=fork();if(pid<0)err(1,"fork");
 if(pid==0){
  if(!s->terminal)setpgid(0,0);
  signal(SIGINT,SIG_DFL);signal(SIGTERM,SIG_DFL);signal(SIGHUP,SIG_DFL);
  if(!s->terminal){close(pipefd[0]);if(dup2(pipefd[1],1)<0 || dup2(pipefd[1],2)<0)_exit(126);close(pipefd[1]);}
  execvp(s->argv[0],s->argv);dprintf(2,"build-bsd: execute %s: %s\n",s->argv[0],strerror(errno));_exit(127);
 }
 child_pid=pid;if(!s->terminal)setpgid(pid,pid);
 if(!s->terminal){
  char buffer[16384];ssize_t n;close(pipefd[1]);
  while((n=read(pipefd[0],buffer,sizeof(buffer)))!=0){
   if(n<0){if(errno==EINTR)continue;kill(-pid,SIGTERM);break;}
   for(int target=0;target<2;target++){ssize_t off=0;int fd=target?STDOUT_FILENO:log;while(off<n){ssize_t written=write(fd,buffer+off,n-off);if(written<0 && errno==EINTR)continue;if(written<=0){kill(-pid,SIGTERM);interrupted=SIGTERM;break;}off+=written;}}
  }
  close(pipefd[0]);close(log);
 }
 while(waitpid(pid,&wstatus,0)<0)if(errno!=EINTR)err(1,"waitpid");child_pid=0;
 if(interrupted)return 128+interrupted;
 return WIFEXITED(wstatus)?WEXITSTATUS(wstatus):128+WTERMSIG(wstatus);
}
static int
media_checksums(void)
{
 const char *names[]={"disc1.iso","memstick.img"};
 const char *algorithms[]={"SHA256","SHA512"};
 for(size_t a=0;a<nitems(algorithms);a++) {
  char *output=format("%s/CHECKSUM.%s",get("output"),algorithms[a]);
  int fd=open(output,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
  if(fd<0)return -1;
  for(size_t i=0;i<nitems(names);i++) {
   if((i==0 && !strcmp(get("media-format"),"memstick")) || (i==1 && !strcmp(get("media-format"),"iso")))continue;
   char *path=format("%s/%s",get("output"),names[i]),digest[SHA512_DIGEST_STRING_LENGTH];struct stat st;
   if(lstat(path,&st)<0 || !S_ISREG(st.st_mode) || st.st_size==0 || !(a?SHA512_File(path,digest):SHA256_File(path,digest))){close(fd);return -1;}
   if(dprintf(fd,"%s (%s) = %s\n",algorithms[a],names[i],digest)<0){close(fd);return -1;}
   free(path);
  }
  if(fsync(fd)<0 || close(fd)<0)return -1;
  free(output);
 }
 return 0;
}
static void
sanitize(void)
{
 const char *names[]={"MAKEFLAGS","MFLAGS","MAKEOVERRIDES","MAKELEVEL","MAKEOBJDIRPREFIX","DESTDIR","DISTDIR","SRCCONF","SRC_ENV_CONF","__MAKE_CONF","ALLOW_DEBUG_MALLOC","TARGET","TARGET_ARCH","PKG_REPO_SIGNING_KEY","HARDWARE_SIGNING_KEY","KERNCONFDIR","REPODIR","PUBLISH_REPODIR","BASE_REPOSITORY","HARDWARE_REPO","COMPLETE_REPOSITORY","WSTAGEDIR","KSTAGEDIR","SSTAGEDIR"};
 for(size_t i=0;i<nitems(names);i++)unsetenv(names[i]);
}
int
main(int argc,char **argv)
{
 setprogname("build-bsd");umask(077);
 if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")))
  usage_status(0);
 if(argc==3 && !strcmp(argv[1],"status")){
  char *path=format("%s/status",argv[2]);regular(path,false);FILE *fp=fopen(path,"r");if(!fp)err(1,"status");char b[4096];while(fgets(b,sizeof(b),fp))fputs(b,stdout);if(ferror(fp))err(1,"status");fclose(fp);return 0;
 }
 char stamp[32];time_t now=time(NULL);struct tm utc;gmtime_r(&now,&utc);strftime(stamp,sizeof(stamp),"%Y%m%dT%H%M%SZ",&utc);
 request.run=format(RUNS "/%s-%ld",stamp,(long)getpid());request.native=format("%s/native-tools",request.run);
 parse(argc,argv);validate();plan();sanitize();
 if(!request.plan){
  mkdirs(OBJECT "/usr/src");int lock=open(OBJECT "/usr/src/.bsd-build.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
  if(lock<0 || flock(lock,LOCK_EX|LOCK_NB)<0)err(1,"build lock");
  mkdirs(RUNS);if(mkdir(request.run,0700)<0)err(1,"run directory");
  signal(SIGINT,signal_handler);signal(SIGTERM,signal_handler);signal(SIGHUP,signal_handler);signal(SIGPIPE,SIG_IGN);
 }
 show_request();
 for(size_t i=0;i<request.count;i++){
  struct step *s=&request.steps[i];show_step(s,i+1);if(request.plan)continue;
  status("running",s->name,0);int code=execute(s,i+1);
  if(code){status("failed",s->name,code);fprintf(stderr,"failed step=%s exit=%d logs=%s\n",s->name,code,request.run);return code;}
 }
 if(!request.plan && action("media") && media_checksums()<0){status("failed","media-checksums",1);warn("media checksums");return 1;}
 if(!request.plan){status("complete","",0);printf("complete action=%s logs=%s %s=%s\n",request.action,request.run,action("media")?"output":"stage",get("output"));}
 return 0;
}
