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
 S("pkg-package",""), S("pkg-package-sha256",""), S("package-tool",""),
 S("application-selection",""),
 S("root",""), S("output",""), S("repository",""),
 S("snapshot-abi",""), S("snapshot-osversion",""),
 S("database-pkg",""), S("database-sqlite",""), S("database-contract",""), S("database-policy",""), S("database-osversion",""),
 S("boot-media-makefs",""), S("boot-media-mkimg",""), S("boot-efi-fallback",""), S("boot-esp-mib",""), S("boot-free-percent",""),
 S("loader-anchors",""),
 S("boot-manifest-verifier",""),
 S("boot-loader-build",""), S("boot-loader-build-sha256",""),
 S("boot-efi-path",""), S("boot-efi-signer",""), S("boot-efi-signature-verifier",""),
 S("boot-efi-signing-key",""), S("boot-efi-signing-certificate",""),
 S("boot-signing-key",""), S("boot-signing-certificate",""), S("boot-openssl",""),
 S("capsule-validator",""), S("capsule-validator-sha256",""),
 S("configuration-base",""), S("configuration-changes",""), S("configuration-parser",""), S("configuration-parser-sha256",""),
 S("boot-observation-policy",""),
 S("boot-image",""), S("boot-archive",""), S("image-receipt",""), S("boot-generated",""), S("boot-policy",""), S("boot-verity-image",""), S("boot-verity-descriptor",""), S("boot-root-path",""),
 S("image-verity-policy",""), S("construction-receipt",""), S("image-makefs",""), S("image-mdconfig",""), S("image-mount",""), S("image-umount",""),
 S("state-plan",""), S("storage-layout-policy",""), S("extract-tar",""), S("package-selection",""), S("inventory",""), S("generated",""), S("construction-timeout","300"), S("certificate-policy",""), S("module-policy",""), S("library-policy",""), S("installation-policy",""),
 S("test-generation-key",""), S("test-generation-certificate",""),
 S("test-case",""),
 S("test-firmware-code",""), S("test-firmware-vars",""),
 S("test-openssl","/usr/bin/openssl"), S("test-uefisign","/usr/sbin/uefisign"),
 S("test-makefs","/usr/sbin/makefs"), S("test-mkimg","/usr/bin/mkimg"),
 S("publish-repository",REPOSITORY), S("ports","/usr/obj/5BSD-ports"),
 S("hardware-profile",""), S("distfiles",""),
 S("bootenv",""), S("clone-from",""), S("be-root",""), S("media-format","all"),
 S("qemu","/usr/local/bin/qemu-system-x86_64"),
 S("qemu-data","/usr/local/share/qemu"), S("uefi-vars-tool","/usr/local/bin/virt-fw-vars"),
 S("bazel","/usr/local/bin/bazel"), S("bazel-inputs",""), S("bazel-modules",""),
 S("format","text"), S("build-backend","bsd-make"),
 B("incremental"), B("candidate-publication"), B("image-boot-archive"),
 B("relaxed-signatures"), B("allow-debug-publication"), B("production")
#undef S
#undef B
};
struct step { char *name, *argv[MAX_ARGS]; size_t argc; bool terminal; };
struct request {
 const char *action, *target, *arch;
 char *run, *native;
 unsigned jobs;
 bool plan, json, packages, cross, production, hardware;
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
static bool firmware_test(void) { return action("secureboot-test") && !strcmp(get("test-case"),"firmware"); }
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
 fprintf(out, "usage: build-bsd [plan] build|world|kernel|stage|packages|sign|verify|inventory|inventory-audit|reconcile|construct|image|boot-check|boot-stage|boot-observe|compose-config|state-storage|snapshot|deploy|bsdinstall|media|loader-build|secureboot-test|bazel-test [options]\n"
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
 if(!oneof(request.action,"build|world|kernel|stage|packages|sign|verify|inventory|inventory-audit|reconcile|construct|image|boot-check|boot-stage|boot-observe|compose-config|state-storage|snapshot|deploy|bsdinstall|media|loader-build|secureboot-test|bazel-test"))usage();
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
/* category/port[@flavor], as release/scripts/native-hardware.py accepts it. */
static bool
port_origin(const char *s)
{
 const char *category="abcdefghijklmnopqrstuvwxyz0123456789+_.-";
 const char *name="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_.-";
 size_t n=strspn(s,category);
 if(!n || s[n]!='/')return false;
 s+=n+1;n=strspn(s,name);
 if(!n)return false;
 s+=n;
 if(*s=='@'){n=strspn(++s,name);if(!n)return false;s+=n;}
 return !*s;
}
/*
 * A profile whose only entry is no-hardware-ports builds no hardware ports.
 * The hardware stage reads the same grammar in native-hardware.py, and
 * tests/hardware-profile-cases pins both readers: ASCII text in lines ended
 * by a newline, "#" starts a comment, and blanks, tabs and carriage returns
 * around an entry are ignored.
 */
static bool
profile_has_ports(const char *path)
{
 FILE *fp=fopen(path,"r");char *line=NULL;size_t size=0;ssize_t length;unsigned none=0,ports=0;
 if(!fp)err(1,"hardware profile");
 while((length=getline(&line,&size,fp))>=0){
  for(ssize_t i=0;i<length;i++)if(!line[i] || (line[i]&0x80))fail("hardware profile must be ASCII text");
  line[strcspn(line,"#\n")]='\0';
  char *entry=line+strspn(line," \t\r");size_t end=strlen(entry);
  while(end && strchr(" \t\r",entry[end-1]))entry[--end]='\0';
  if(!strcmp(entry,"no-hardware-ports"))none++;
  else if(port_origin(entry))ports++;
  else if(*entry)errx(1,"invalid port in hardware profile: %s",entry);
 }
 if(ferror(fp))err(1,"hardware profile");
 free(line);fclose(fp);
 if(!none && !ports)fail("empty hardware profile");
 if(none && (ports || none>1))fail("no-hardware-ports must be the only hardware profile entry");
 return !none;
}
static void
validate(void)
{
 char host[64];size_t len=sizeof(host);struct stat st;
 if(action("state-storage")){if(!*get("state-plan"))fail("state-storage requires --state-plan");regular(get("state-plan"),false);canonical("state-plan");}
 else if(selected("state-plan"))fail("--state-plan applies only to state-storage");
 if(selected("capsule-validator") || selected("capsule-validator-sha256")) {
  if(!action("compose-config"))fail("Capsule validator applies only to compose-config");
  const char *hash=get("capsule-validator-sha256");
  if(!*get("capsule-validator") || strlen(hash)!=64 || strspn(hash,"0123456789abcdef")!=64)
   fail("Capsule validator requires a selected executable and lowercase SHA256");
  regular(get("capsule-validator"),false);canonical("capsule-validator");
 }
 const char *composition_inputs[]={"configuration-base","configuration-changes","configuration-parser"};
 for(size_t i=0;i<nitems(composition_inputs);i++) {
  if(action("compose-config")){if(!*get(composition_inputs[i]))fail("compose-config requires base, changes and parser");regular(get(composition_inputs[i]),false);canonical(composition_inputs[i]);}
  else if(selected(composition_inputs[i]))fail("configuration composition inputs apply only to compose-config");
 }
 if(action("compose-config")) {
  const char *hash=get("configuration-parser-sha256");
  if(strlen(hash)!=64 || strspn(hash,"0123456789abcdef")!=64)fail("compose-config requires a lowercase parser SHA256");
 } else if(selected("configuration-parser-sha256"))fail("parser hash applies only to compose-config");

 if(action("boot-observe")){if(!*get("boot-observation-policy"))fail("boot-observe requires --boot-observation-policy");regular(get("boot-observation-policy"),false);canonical("boot-observation-policy");}
 else if(selected("boot-observation-policy"))fail("--boot-observation-policy applies only to boot-observe");
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
 if(action("boot-observe") && strcmp(request.arch,"amd64"))fail("boot-observe currently requires amd64");
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
 if(selected("package-tool")) {
  if(!request.packages && !action("snapshot"))fail("--package-tool applies only to build, packages or snapshot");
  regular(get("package-tool"),false);canonical("package-tool");
  if(strspn(get("package-tool"),"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-.+")!=strlen(get("package-tool")))fail("--package-tool path must contain only make/shell-safe characters");
  if(access(get("package-tool"),X_OK)<0)fail("--package-tool must be executable");
 }
 if(*get("pkg-package") || *get("pkg-package-sha256")) {
  if(!request.packages)fail("bootstrap pkg inputs apply only to build or packages");
  const char *hash=get("pkg-package-sha256");
  if(!*get("pkg-package") || strlen(hash)!=64 || strspn(hash,"0123456789abcdefABCDEF")!=64)fail("bootstrap pkg requires --pkg-package and a 64-digit --pkg-package-sha256");
  regular(get("pkg-package"),false);canonical("pkg-package");
  if(strspn(get("pkg-package"),"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-.+")!=strlen(get("pkg-package")))fail("--pkg-package path must contain only make/shell-safe characters");
 }
 if(selected("application-selection")) {
  if(!request.packages)fail("--application-selection applies only to build or packages");
  regular(get("application-selection"),false);canonical("application-selection");
  if(strspn(get("application-selection"),"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-.+")!=strlen(get("application-selection")))fail("--application-selection path must contain only make/shell-safe characters");
 }
 if(selected("ports") && !request.packages)fail("--ports applies only to packages");
 if(selected("candidate-publication") && !request.packages)fail("--candidate-publication applies only to packages/build");
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
  if(*get("output"))fail("packages uses maintained package staging directories");
  if(!*get("hardware-profile"))set("hardware-profile",format(SOURCE "/release/tools/hardware-ports.%s",request.arch),false);
  if(access(get("hardware-profile"),R_OK)<0)errx(1,"native hardware backend requires a readable hardware profile: %s",get("hardware-profile"));
  regular(get("hardware-profile"),false);canonical("hardware-profile");
  /* Without ports nothing is compiled for the target, so no ports checkout or native builder is needed. */
  request.hardware=profile_has_ports(get("hardware-profile"));
  if(request.hardware){
   if(request.cross)fail("native hardware backend cannot publish a foreign target");
   if(access(format("%s/Mk/bsd.port.mk",get("ports")),R_OK)<0)fail("ports checkout is missing");regular(format("%s/Mk/bsd.port.mk",get("ports")),false);canonical("ports");
   if(!*get("distfiles"))set("distfiles",format("%s/distfiles",get("ports")),false);canonical("distfiles");
  }
 } else if(*get("hardware-profile") || *get("distfiles"))fail("hardware profile and distfiles apply only to build or packages");
 if(selected("media-format") && !action("media"))fail("--media-format applies only to media");
 if(!oneof(get("media-format"),"all|iso|memstick"))fail("invalid media format");
 if(action("snapshot")) {
  if(!*get("repository") || !*get("pkg-public-key") || !*get("package-tool") || !*get("snapshot-abi") || !*get("snapshot-osversion"))fail("snapshot requires repository, public trust key, package tool, ABI and OS version");
  if(strcmp(get("signing"),"unsigned"))fail("snapshot verifies consumer trust and does not sign");
  regular(get("pkg-public-key"),false);canonical("pkg-public-key");canonical("repository");regular(format("%s/publication.json",get("repository")),false);
  const char *abi=get("snapshot-abi"),*version=get("snapshot-osversion");char *end;errno=0;unsigned long n=strtoul(version,&end,10);
  if(strlen(abi)>128 || strspn(abi,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_-.")!=strlen(abi))fail("invalid snapshot ABI");
  if(strspn(version,"0123456789")!=strlen(version) || errno || *end || !n || n>INT_MAX)fail("snapshot OS version must be a positive 32-bit integer");
 } else if(selected("snapshot-abi") || selected("snapshot-osversion"))fail("snapshot target inputs apply only to snapshot");
 bool deploy=action("deploy") || action("bsdinstall") || action("media");
 if(deploy){
  regular(get("public-key"),false);canonical("public-key");regular(get("pkg-public-key"),false);canonical("pkg-public-key");canonical("repository");regular(format("%s/publication.json",get("repository")),false);
  if(action("deploy")){if(!*get("root")==!*get("bootenv"))fail("deploy requires exactly one of --root or --bootenv");}
  else if(*get("root") || *get("bootenv") || *get("clone-from") || *get("be-root"))fail("--root/--bootenv/--clone-from apply only to deploy");
  if(*get("bootenv") && (strlen(get("bootenv"))>63 || !isalnum((unsigned char)*get("bootenv")) || strspn(get("bootenv"),"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")!=strlen(get("bootenv"))))fail("invalid boot environment name");
  if((*get("clone-from") || *get("be-root")) && !*get("bootenv"))fail("--clone-from/--be-root require --bootenv");
  if(*get("be-root") && !*get("clone-from"))fail("--be-root requires --clone-from");
  if(action("bsdinstall") && request.cross)fail("bsdinstall requires native architecture");
 } else if((!action("snapshot") && (*get("repository") || *get("pkg-public-key"))) || *get("bootenv") || *get("clone-from") || *get("be-root"))fail("repository settings apply only to deployment or snapshot");
 if(action("verify") || action("sign")){
  if(!*get("root"))fail("requires --root DIRECTORY");canonical("root");
  if(!strcmp(get("root"),"/") || stat(get("root"),&st)<0 || !S_ISDIR(st.st_mode))fail("requires an alternate root directory");
  if(action("verify")){regular(get("public-key"),false);canonical("public-key");}
  if(action("sign") && strcmp(get("signing"),"signed"))fail("sign requires signed mode and --key");
 } else if(!deploy && !action("secureboot-test") && !action("reconcile") && !action("construct") && !action("image") && (*get("root") || *get("public-key")))fail("--root and --public-key apply only to verify/sign/deploy");
 if(selected("storage-layout-policy")) {
  if(!action("reconcile") && !action("image") && !action("construct"))fail("--storage-layout-policy applies only to construct, reconcile or image");
  regular(get("storage-layout-policy"),false);canonical("storage-layout-policy");
 }
 if(action("inventory")) {
  regular(get("package-selection"),false);canonical("package-selection");
  if(strcmp(get("signing"),"unsigned"))fail("inventory does not sign or authenticate packages");
 } else if(selected("package-selection"))fail("--package-selection applies only to inventory");
 if(action("reconcile") || action("construct") || action("image")) {
  if(!*get("root"))fail("offline generation operation requires --root");
  if(lstat(get("root"),&st)<0 || S_ISLNK(st.st_mode))fail("offline generation root must be a directory, not a symlink");canonical("root");
  if(!strcmp(get("root"),"/") || stat(get("root"),&st)<0 || !S_ISDIR(st.st_mode))fail("requires an alternate root directory");
  regular(get("inventory"),false);canonical("inventory");regular(get("generated"),false);canonical("generated");
  if(strcmp(get("signing"),"unsigned") || *get("public-key"))fail("offline generation operations do not authenticate or sign inputs");
 } else if(action("inventory-audit")) {
  regular(get("inventory"),false);canonical("inventory");
  if(*get("generated") || strcmp(get("signing"),"unsigned"))fail("inventory-audit accepts inventory only and does not sign inputs");
 } else if(action("deploy")) {
  if(*get("inventory"))fail("deploy derives inventory from authenticated package fetch");
  if(!*get("generated"))fail("deploy requires --generated construction manifest");
  regular(get("generated"),false);canonical("generated");
 } else if(*get("inventory") || *get("generated"))fail("--inventory applies only to reconcile, construct, image or inventory-audit; --generated applies only to reconcile, construct, image or deploy");
 {
  const char *names[]={"construction-receipt","image-makefs","image-mdconfig","image-mount","image-umount"};
  for(size_t i=0;i<nitems(names);i++) {
   if(action("image")) {if(!*get(names[i]))fail("image requires a construction receipt and all four explicit image tools");regular(get(names[i]),false);canonical(names[i]);}
   else if(selected(names[i]))fail("image inputs apply only to image");
  }
 }
 {
  const char *names[]={"boot-image","boot-archive","image-receipt"};
  for(size_t i=0;i<nitems(names);i++) {
   if(action("boot-check") || action("boot-stage")) {if(!*get(names[i]))fail("boot-check/boot-stage require image, boot archive and image receipt");regular(get(names[i]),false);canonical(names[i]);}
   else if(selected(names[i]))fail("boot inputs apply only to boot-check or boot-stage");
  }
  if((action("boot-check") || action("boot-stage")) && strcmp(get("signing"),"unsigned"))fail("boot-check does not authenticate or sign inputs");
 }
 if(selected("boot-signing-key") || selected("boot-signing-certificate") || selected("boot-openssl")) {
  if(!action("boot-stage") || !*get("boot-policy") || !*get("boot-generated") || !*get("boot-signing-key") || !*get("boot-signing-certificate") || !*get("boot-openssl"))fail("boot manifest signing requires boot-stage, --boot-policy, --boot-generated, --boot-signing-key, --boot-signing-certificate and --boot-openssl");
  regular(get("boot-signing-key"),true);canonical("boot-signing-key");
  regular(get("boot-signing-certificate"),false);canonical("boot-signing-certificate");
  regular(get("boot-openssl"),false);canonical("boot-openssl");
  if(access(get("boot-openssl"),X_OK)<0)fail("--boot-openssl must be executable");
 }
 if(selected("boot-efi-signing-key") || selected("boot-efi-signing-certificate")) {
  if(!action("boot-stage") || !*get("boot-efi-path") || !*get("boot-efi-signing-key") || !*get("boot-efi-signing-certificate"))fail("separate EFI signing requires boot-stage EFI inputs and both key and certificate");
  regular(get("boot-efi-signing-key"),true);canonical("boot-efi-signing-key");
  regular(get("boot-efi-signing-certificate"),false);canonical("boot-efi-signing-certificate");
 }
 if(selected("boot-efi-signature-verifier") || selected("boot-efi-path") || selected("boot-efi-signer") || selected("boot-loader-build") || selected("boot-loader-build-sha256") || selected("boot-manifest-verifier")) {
  if(!action("boot-stage") || !*get("boot-signing-key") || !*get("boot-efi-path") || !*get("boot-efi-signer"))fail("EFI signing requires boot-stage manifest signing, --boot-efi-path and --boot-efi-signer");
  const char *pin=get("boot-loader-build-sha256");
  if(!*get("boot-loader-build") || strlen(pin)!=64 || strspn(pin,"0123456789abcdef")!=64)fail("EFI signing requires --boot-loader-build and its lowercase --boot-loader-build-sha256");
  regular(get("boot-loader-build"),false);canonical("boot-loader-build");
  if(!*get("boot-manifest-verifier"))fail("EFI signing requires --boot-manifest-verifier");
  regular(get("boot-manifest-verifier"),false);canonical("boot-manifest-verifier");
  if(access(get("boot-manifest-verifier"),X_OK)<0)fail("manifest verifier must be executable");
  if(strncmp(get("boot-efi-path"),"/boot/",6))fail("EFI loader must be a boot inventory path");
  if(!*get("boot-efi-signature-verifier"))fail("EFI signing requires --boot-efi-signature-verifier");
  regular(get("boot-efi-signature-verifier"),false);canonical("boot-efi-signature-verifier");
  if(access(get("boot-efi-signature-verifier"),X_OK)<0)fail("EFI signature verifier must be executable");
  regular(get("boot-efi-signer"),false);canonical("boot-efi-signer");
  if(access(get("boot-efi-signer"),X_OK)<0)fail("EFI signer must be executable");
 }
 {
  const char *media[]={"boot-media-makefs","boot-media-mkimg","boot-efi-fallback","boot-esp-mib","boot-free-percent"};
  bool requested=false;for(size_t i=0;i<nitems(media);i++)if(selected(media[i]))requested=true;
  if(requested) {
   if(!action("boot-stage") || !*get("boot-efi-path") || !*get("boot-root-path"))fail("boot media requires boot-stage EFI signing and --boot-root-path");
   for(size_t i=0;i<nitems(media);i++)if(!*get(media[i]))fail("boot media requires both tools, fallback name, ESP capacity and free percentage");
   for(size_t i=0;i<2;i++){regular(get(media[i]),false);canonical(media[i]);if(access(get(media[i]),X_OK)<0)fail("boot media tool must be executable");}
   const char *fallback=get("boot-efi-fallback");size_t length=strlen(fallback);
   if(length<9 || strncmp(fallback,"BOOT",4) || strcmp(fallback+length-4,".EFI") || strspn(fallback+4,"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")!=length-8)fail("invalid boot EFI fallback name");
   for(size_t i=3;i<5;i++){const char *v=get(media[i]);if(strlen(v)>4 || strspn(v,"0123456789")!=strlen(v))fail("invalid boot media capacity");unsigned long n=strtoul(v,NULL,10);if((i==3 && (n<16 || n>1024)) || (i==4 && n>50))fail("invalid boot media capacity");}
  }
 }
 if(selected("boot-root-path")) {
  if(!action("boot-stage") || strncmp(get("boot-root-path"),"/boot/",6))fail("--boot-root-path requires boot-stage and a boot inventory path");
 }
 if(selected("boot-verity-image") || selected("boot-verity-descriptor")) {
  if((!action("boot-check") && !action("boot-stage")) || !*get("boot-verity-image") || !*get("boot-verity-descriptor"))fail("verity artifact inputs require boot-check/boot-stage and both image and descriptor");
  if(action("boot-stage") && !*get("boot-policy"))fail("disk staging requires an explicit boot policy");
  regular(get("boot-verity-image"),false);canonical("boot-verity-image");
  regular(get("boot-verity-descriptor"),false);canonical("boot-verity-descriptor");
 }
 if(selected("boot-policy")) {
  if(!action("boot-stage") && !action("boot-check"))fail("--boot-policy applies only to boot-check or boot-stage");
  regular(get("boot-policy"),false);canonical("boot-policy");
 }
 if(selected("boot-generated")) {
  if(!action("boot-stage"))fail("--boot-generated applies only to boot-stage");
  regular(get("boot-generated"),false);canonical("boot-generated");
 }
 if(selected("image-verity-policy")) {
  if(!action("image") || !*get("storage-layout-policy"))fail("--image-verity-policy requires image with --storage-layout-policy");
  regular(get("image-verity-policy"),false);canonical("image-verity-policy");
 }
 if(selected("image-boot-archive") && !action("image"))fail("--image-boot-archive applies only to image");
 if(selected("extract-tar")) {
  if(!action("construct"))fail("--extract-tar applies only to construct");
  regular(get("extract-tar"),false);canonical("extract-tar");
 }
 if(selected("installation-policy")) {
  if(!action("construct"))fail("--installation-policy applies only to construct");
  if(!*get("installation-policy"))fail("--installation-policy requires a file");
  regular(get("installation-policy"),false);canonical("installation-policy");
 }
 if(selected("library-policy")) {
  if(!action("construct"))fail("--library-policy applies only to construct");
  if(!*get("library-policy"))fail("--library-policy requires a file");
  regular(get("library-policy"),false);canonical("library-policy");
 }
 if(selected("module-policy")) {
  if(!action("construct"))fail("--module-policy applies only to construct");
  if(!*get("module-policy"))fail("--module-policy requires a file");
  regular(get("module-policy"),false);canonical("module-policy");
 }
 if(selected("certificate-policy")) {
  if(!action("construct"))fail("--certificate-policy applies only to construct");
  if(!*get("certificate-policy"))fail("--certificate-policy requires a file");
  regular(get("certificate-policy"),false);canonical("certificate-policy");
 }
 {
  const char *names[]={"database-pkg","database-sqlite","database-contract","database-policy","database-osversion"};
  bool any=false;for(size_t i=0;i<5;i++)if(selected(names[i]))any=true;
  if(any) {
   if(!action("construct"))fail("database inputs apply only to construct");
   for(size_t i=0;i<5;i++)if(!*get(names[i]))fail("database construction requires all five explicit database inputs");
   for(size_t i=0;i<4;i++){regular(get(names[i]),false);canonical(names[i]);}
   const char *value=get("database-osversion");char *end;errno=0;unsigned long version=strtoul(value,&end,10);
   if(strspn(value,"0123456789")!=strlen(value) || errno || *end || !version || version>INT_MAX)fail("database OSVERSION must be a positive 32-bit integer");
  }
 }
 if(action("construct")) {
  const char *value=get("construction-timeout");char *end;errno=0;unsigned long seconds=strtoul(value,&end,10);
  if(!*value || strspn(value,"0123456789")!=strlen(value) || errno || *end || !seconds || seconds>86400)fail("--construction-timeout must be between 1 and 86400 seconds");
 } else if(selected("construction-timeout"))fail("--construction-timeout applies only to construct");
 if((!strcmp(get("test-case"),"firmware-signed-manifest") || !strcmp(get("test-case"),"revoked-generation-manifest")) && !*get("test-generation-key"))fail("generation trust cases require explicit generation key and certificate");
 if(selected("test-generation-key") || selected("test-generation-certificate")) {
  if(!action("secureboot-test") || !*get("test-generation-key") || !*get("test-generation-certificate"))fail("generation test signing requires secureboot-test and both key and certificate");
  if(!*get("test-case") || !strcmp(get("test-case"),"second-db-cert") || !strcmp(get("test-case"),"second-dbx-cert") || !strcmp(get("test-case"),"second-dbx-hash"))fail("generation test signing requires an explicit case independent of secondary firmware db trust");
  regular(get("test-generation-key"),true);canonical("test-generation-key");
  regular(get("test-generation-certificate"),false);canonical("test-generation-certificate");
  const char *cert=get("test-generation-certificate");
  if(strspn(cert,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-")!=strlen(cert))fail("generation certificate path must be a literal make word using letters, digits, slash, dot, underscore or dash");
 }
 if(action("bazel-test")) {
  if(strcmp(host,"amd64"))fail("bazel-test currently requires an amd64 execution SDK and host");
  if((request.cross || strcmp(request.arch,"amd64")) && !*get("bazel-inputs"))fail("cross-target bazel-test requires explicit source graph --bazel-inputs");
  if(!selected("bazel") && access(get("bazel"),F_OK)<0)fail("bazel-test uses /usr/local/bin/bazel (the bazel9 package, Bazel 9 or later) by default; install it or select another Bazel 9 executable with --bazel");
  canonical("bazel");regular(get("bazel"),false);
  if(*get("bazel-inputs")){
   if(selected("bazel-modules"))fail("--bazel-modules selects the declared pilot's offline module inputs; native --bazel-inputs names its own");
   canonical("bazel-inputs");regular(get("bazel-inputs"),false);
  } else {
   if(!*get("bazel-modules"))fail("bazel-test requires --bazel-modules: the offline Bazel 9 module inputs (repository cache, distdirs, optional JDK) of the declared pilot");
   canonical("bazel-modules");regular(get("bazel-modules"),false);
  }
  if(access(get("bazel"),X_OK)<0)fail("--bazel must be executable");
  if(strcmp(get("signing"),"unsigned") || yes("incremental"))fail("bazel-test requires unsigned fresh qualification output");
  if(selected("src-conf") || selected("make-conf") || selected("build-profile") || selected("production"))fail("bazel-test uses its staged development SDK and fixed comparison configuration");
 } else if(selected("bazel") || selected("bazel-inputs") || selected("bazel-modules"))fail("--bazel, --bazel-inputs and --bazel-modules apply only to bazel-test");
 if(action("loader-build")) {
  if(request.cross || strcmp(request.arch,"amd64"))fail("loader-build currently requires native amd64");
  if(!*get("loader-anchors"))fail("loader-build requires --loader-anchors");
  regular(get("loader-anchors"),false);canonical("loader-anchors");
  if(strcmp(get("signing"),"unsigned") || yes("incremental"))fail("loader-build produces an unsigned loader in a fresh object tree");
  if((selected("src-conf") && strcmp(get("src-conf"),"/dev/null")) ||
     (selected("make-conf") && strcmp(get("make-conf"),"/dev/null")))fail("loader-build uses a fixed trust profile with /dev/null make configurations");
  set("src-conf","/dev/null",false);set("make-conf","/dev/null",false);
 } else if(selected("loader-anchors"))fail("--loader-anchors applies only to loader-build");
 if(action("secureboot-test")) {
  if(selected("test-case") && (!*get("test-case") || strlen(get("test-case"))>80 || strspn(get("test-case"),"abcdefghijklmnopqrstuvwxyz0123456789-")!=strlen(get("test-case"))))fail("--test-case requires one runner case name");
  if(request.cross || strcmp(request.arch,"amd64"))fail("Secure Boot qualification requires native amd64");
  if(!firmware_test()) {
  if(!*get("root"))fail("secureboot-test requires --root with a matching staged kernel");
  canonical("root");
  if(!under(get("root"),OBJECT))fail("qualification root must be staged under /usr/obj");
  regular(format("%s/boot/kernel/kernel",get("root")),false);
  } else if(*get("root") || *get("test-generation-key"))fail("firmware-only tests do not use a staged root or generation key");
  if(strcmp(get("signing"),"unsigned") || *get("public-key") || yes("incremental"))fail("secureboot-test generates disposable keys and always rebuilds its loader");
  const char *programs[]={"qemu","uefi-vars-tool"};
  for(size_t i=0;i<nitems(programs);i++){canonical(programs[i]);regular(get(programs[i]),false);}
  canonical("qemu-data");
  if(firmware_test()) {
   if(!*get("test-firmware-code") || !*get("test-firmware-vars"))fail("firmware tests require explicit --test-firmware-code and --test-firmware-vars");
   const char *inputs[]={"test-firmware-code","test-firmware-vars","test-openssl","test-uefisign","test-makefs","test-mkimg"};
   for(size_t i=0;i<nitems(inputs);i++){canonical(inputs[i]);regular(get(inputs[i]),false);}
  } else {
  regular(format("%s/edk2-x86_64-secure-code.fd",get("qemu-data")),false);
  regular(format("%s/edk2-i386-vars.fd",get("qemu-data")),false);
  }
 } else if(selected("test-case") || selected("qemu") || selected("qemu-data") || selected("uefi-vars-tool"))fail("QEMU options apply only to secureboot-test");
 {
  const char *inputs[]={"test-firmware-code","test-firmware-vars","test-openssl","test-uefisign","test-makefs","test-mkimg"};
  for(size_t i=0;i<nitems(inputs);i++)if(selected(inputs[i]) && !firmware_test())fail("firmware inputs require secureboot-test --test-case firmware");
 }
 if(*get("output") && !action("inventory") && !action("inventory-audit") && !action("stage") && !action("media") && !action("secureboot-test") && !action("reconcile") && !action("construct") && !action("image") && !action("boot-stage") && !action("boot-observe") && !action("compose-config") && !action("snapshot") && !action("state-storage") && !action("loader-build") && !action("bazel-test"))fail("--output applies only to stage, media, secureboot-test, reconcile, construct, image or boot-observe");
 if(action("inventory") || action("inventory-audit") || action("stage") || action("media") || action("secureboot-test") || action("reconcile") || action("construct") || action("image") || action("boot-stage") || action("boot-observe") || action("compose-config") || action("snapshot") || action("state-storage") || action("loader-build") || action("bazel-test")){
  if(action("snapshot") && !*get("output"))set("output",format("%s/repository",request.run),false);
  if(!*get("output"))set("output",format(OBJECT "/usr/src/%s/%s",action("inventory")?"inventories":action("inventory-audit")?"inventory-audits":action("media")?"media":action("reconcile")?"reconciliation":action("construct")?"construction":action("image")?"images":action("boot-stage")?"boot-stages":action("boot-observe")?"boot-observations":action("compose-config")?"configuration-compositions":action("state-storage")?"state-storage":action("loader-build")?"loaders":action("bazel-test")?"bazel-qualification":"stages",strrchr(request.run,'/')+1),false);
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
 if(action("bazel-test")) {
  s=step("bazel-qualification");args(s,PYTHON,*get("bazel-inputs")?SOURCE "/tools/build/bazel/native-qualify.py":SOURCE "/tools/build/bazel/qualify.py",
      "--src",SOURCE,"--objtop",OBJECT "/usr/src/amd64.amd64",
      "--bazel",get("bazel"),"--output",get("output"),"--jobs",format("%u",request.jobs),NULL);
  if(*get("bazel-inputs"))args(s,"--inputs",get("bazel-inputs"),"--target-arch",request.arch,NULL);
  else args(s,"--bzlmod-inputs",get("bazel-modules"),NULL);
  return;
 }
 if(action("loader-build")) {
  s=step("loader-build");args(s,PYTHON,HELPERS "loader_build.py","--anchors",get("loader-anchors"),"--output",get("output"),"--jobs",format("%u",request.jobs),NULL);return;
 }
 if(action("inventory")) {
  char *directory=strdup(get("output"));*strrchr(directory,'/')=0;
  s=step("inventory-parent");args(s,"mkdir","-p",directory,NULL);free(directory);
  s=step("inventory-directory");args(s,"mkdir","-m","0700","--",get("output"),NULL);
  s=step("inventory");args(s,PYTHON,HELPERS "package_inventory.py","--selection",get("package-selection"),"--output",format("%s/inventory.json",get("output")),NULL);return;
 }
 if(action("state-storage")){s=step("state-storage");args(s,PYTHON,HELPERS "state_storage.py","--plan",get("state-plan"),"--output",get("output"),NULL);return;}
 if(action("snapshot")){s=step("snapshot");args(s,PYTHON,SOURCE "/release/scripts/hardware-packages.py","copy-signed-repository","--repository",get("repository"),"--output",get("output"),"--public-key",get("pkg-public-key"),"--pkg",get("package-tool"),"--abi",get("snapshot-abi"),"--osversion",get("snapshot-osversion"),NULL);return;}
 if(action("compose-config")){s=step("compose-config");args(s,PYTHON,HELPERS "configuration_compose.py","--base",get("configuration-base"),"--changes",get("configuration-changes"),"--ucl-parser",get("configuration-parser"),"--ucl-parser-sha256",get("configuration-parser-sha256"),"--output",get("output"),NULL);if(*get("capsule-validator"))args(s,"--capsule-validator",get("capsule-validator"),"--capsule-validator-sha256",get("capsule-validator-sha256"),NULL);return;}
 if(action("boot-observe")){s=step("boot-observe");args(s,PYTHON,SOURCE "/tools/test/boot-observe/run.py","--policy",get("boot-observation-policy"),"--work",get("output"),NULL);return;}
 if(action("boot-check") || action("boot-stage")) {
  s=step(request.action);args(s,PYTHON,HELPERS "generation_boot.py","--image",get("boot-image"),"--boot-archive",get("boot-archive"),"--image-receipt",get("image-receipt"),NULL);if(action("boot-stage"))args(s,"--output",get("output"),NULL);if(*get("boot-generated"))args(s,"--generated",get("boot-generated"),NULL);if(*get("boot-policy"))args(s,"--boot-policy",get("boot-policy"),NULL);if(*get("boot-verity-image"))args(s,"--verity-image",get("boot-verity-image"),"--verity-descriptor",get("boot-verity-descriptor"),NULL);if(*get("boot-root-path"))args(s,"--root-path",get("boot-root-path"),NULL);if(*get("boot-signing-key"))args(s,"--signing-key",get("boot-signing-key"),"--signing-certificate",get("boot-signing-certificate"),"--openssl",get("boot-openssl"),NULL);if(*get("boot-efi-path"))args(s,"--efi-path",get("boot-efi-path"),"--efi-signer",get("boot-efi-signer"),"--efi-signature-verifier",get("boot-efi-signature-verifier"),"--loader-build-receipt",get("boot-loader-build"),"--loader-build-sha256",get("boot-loader-build-sha256"),"--manifest-verifier",get("boot-manifest-verifier"),NULL);if(*get("boot-efi-signing-key"))args(s,"--efi-signing-key",get("boot-efi-signing-key"),"--efi-signing-certificate",get("boot-efi-signing-certificate"),NULL);if(*get("boot-media-makefs"))args(s,"--media-makefs",get("boot-media-makefs"),"--media-mkimg",get("boot-media-mkimg"),"--efi-fallback-name",get("boot-efi-fallback"),"--esp-mib",get("boot-esp-mib"),"--boot-free-percent",get("boot-free-percent"),NULL);return;
 }
 if(action("image")) {
  s=step("image");args(s,PYTHON,HELPERS "generation_image.py","--root",get("root"),"--inventory",get("inventory"),"--generated",get("generated"),"--construction-receipt",get("construction-receipt"),"--output",get("output"),"--makefs",get("image-makefs"),"--mdconfig",get("image-mdconfig"),"--mount",get("image-mount"),"--umount",get("image-umount"),NULL);if(*get("image-verity-policy"))args(s,"--verity-policy",get("image-verity-policy"),NULL);if(!strcmp(get("image-boot-archive"),"yes"))args(s,"--boot-archive",NULL);if(*get("storage-layout-policy"))args(s,"--storage-layout-policy",get("storage-layout-policy"),NULL);return;
 }
 if(action("construct")) {
  s=step("construct");args(s,PYTHON,HELPERS "construction.py","--root",get("root"),"--inventory",get("inventory"),"--generated",get("generated"),"--output",get("output"),"--timeout",get("construction-timeout"),NULL);
  if(*get("extract-tar"))args(s,"--extract-tar",get("extract-tar"),NULL);
  if(*get("database-pkg"))args(s,"--database-pkg",get("database-pkg"),"--database-sqlite",get("database-sqlite"),"--database-contract",get("database-contract"),"--database-policy",get("database-policy"),"--database-osversion",get("database-osversion"),NULL);
  if(*get("module-policy"))args(s,"--module-policy",get("module-policy"),NULL);
  if(*get("library-policy"))args(s,"--library-policy",get("library-policy"),NULL);
  if(*get("installation-policy"))args(s,"--installation-policy",get("installation-policy"),NULL);
  if(*get("storage-layout-policy"))args(s,"--storage-layout-policy",get("storage-layout-policy"),NULL);
  if(*get("certificate-policy"))args(s,"--certificate-policy",get("certificate-policy"),NULL);return;
 }
 if(action("inventory-audit")) {
  char *parent=strdup(get("output"));*strrchr(parent,'/')='\0';
  s=step("audit-parent");args(s,"mkdir","-p",parent,NULL);free(parent);
  s=step("audit-directory");args(s,"mkdir",get("output"),NULL);
  s=step("inventory-audit");args(s,PYTHON,HELPERS "inventory_audit.py","--inventory",get("inventory"),"--output",format("%s/inventory-review.json",get("output")),NULL);return;
 }
 if(action("reconcile")) {
  s=step("reconcile");args(s,PYTHON,HELPERS "generation_check.py","--root",get("root"),"--inventory",get("inventory"),"--generated",get("generated"),"--output",get("output"),NULL);
  if(*get("storage-layout-policy"))args(s,"--storage-layout-policy",get("storage-layout-policy"),NULL);
  return;
 }
 if(action("secureboot-test")) {
  /* Firmware-verification options change shared stand libraries. Keep them
   * out of the world tree, including when the next build is incremental. */
  char *loader_prefix=format("%s/secureboot-obj",request.run);
  char *loader_objtop=format("%s/usr/src/%s.%s",loader_prefix,request.target,request.arch);
  const char *targets[]={"clean","efi-loader"};
  for(size_t i=0;i<nitems(targets);i++) {
   s=step(i?"secureboot-loader":"secureboot-loader-clean");
   args(s,"env",format("MAKEOBJDIRPREFIX=%s",loader_prefix),"make","-C",SOURCE "/stand","-j",format("%u",request.jobs),
       "WITH_BEARSSL=yes","WITH_LOADER_VERIEXEC=yes","WITH_LOADER_EFI_SECUREBOOT=yes",
       "WITHOUT_LOADER_VERIEXEC_VECTX=yes","WITHOUT_FORTH=yes","WITHOUT_LOADER_IA32=yes",NULL);
   if(*get("test-generation-certificate")) {
    arg(s,"WITHOUT_LOADER_EFI_TRUST_DB=yes");
    assignment(s,"TRUST_ANCHORS",get("test-generation-certificate"));
   }
   assignment(s,"SRCCONF",get("src-conf"));assignment(s,"__MAKE_CONF",get("make-conf"));arg(s,targets[i]);
  }
  if(firmware_test()) {
   s=step("secureboot-firmware-probe");args(s,"env","MAKEOBJDIRPREFIX=" OBJECT,"make","-C",SOURCE,"buildenv",
       format("BUILDENV_SHELL=make -C %s/tools/test/secureboot/firmware -j%u BOOTOBJ=%s/stand all",SOURCE,request.jobs,loader_objtop),NULL);
   assignment(s,"SRCCONF",get("src-conf"));assignment(s,"__MAKE_CONF",get("make-conf"));
   s=step("secureboot-firmware-update-probe");args(s,"env","MAKEOBJDIRPREFIX=" OBJECT,"make","-C",SOURCE,"buildenv",
       format("BUILDENV_SHELL=make -C %s/tools/test/secureboot/firmware/update -j%u BOOTOBJ=%s/stand all",SOURCE,request.jobs,loader_objtop),NULL);
   assignment(s,"SRCCONF",get("src-conf"));assignment(s,"__MAKE_CONF",get("make-conf"));
   s=step("secureboot-firmware-evidence-tests");args(s,"env",format("FIRMWARE_TEST_OPENSSL=%s",get("test-openssl")),PYTHON,"-B","-m","unittest","discover","-s",SOURCE "/tools/test/secureboot/firmware","-p","*_test.py",NULL);
   s=step("secureboot-firmware-vm");args(s,PYTHON,"-B",SOURCE "/tools/test/secureboot/firmware/suite.py",
       "--probe",OBJECT "/usr/src/amd64.amd64/tools/test/secureboot/firmware/firmware_probe.efi",
       "--update-probe",OBJECT "/usr/src/amd64.amd64/tools/test/secureboot/firmware/update/firmware_update.efi",
       "--firmware",get("test-firmware-code"),"--variables",get("test-firmware-vars"),
       "--vars-tool",get("uefi-vars-tool"),"--openssl",get("test-openssl"),"--uefisign",get("test-uefisign"),
       "--makefs",get("test-makefs"),"--mkimg",get("test-mkimg"),
       "--qemu",get("qemu"),"--qemu-data",get("qemu-data"),"--work",get("output"),NULL);
   return;
  }
  s=step("secureboot-bootstrap");args(s,"env","MAKEOBJDIRPREFIX=" OBJECT,"make","-C",SOURCE,"buildenv",
      format("BUILDENV_SHELL=sh %s/tools/test/secureboot/build-bootstrap.sh %s %u",SOURCE,SOURCE,request.jobs),NULL);
  assignment(s,"SRCCONF",get("src-conf"));assignment(s,"__MAKE_CONF",get("make-conf"));
  s=step("secureboot-fixture");args(s,"env","MAKEOBJDIRPREFIX=" OBJECT,"make","-C",SOURCE,"buildenv",
      format("BUILDENV_SHELL=make -C %s/tools/test/secureboot -j%u SECUREBOOT_OBJTOP=%s all",SOURCE,request.jobs,loader_objtop),NULL);
  assignment(s,"SRCCONF",get("src-conf"));assignment(s,"__MAKE_CONF",get("make-conf"));
  s=step("secureboot-parser");args(s,OBJECT "/usr/src/amd64.amd64/tools/test/secureboot/efi_database_test",NULL);
  s=step("secureboot-host-tools-directory");args(s,"mkdir","-p",request.native,NULL);
  s=step("secureboot-host-tools");args(s,"make","-C",request.native,"-f",HELPERS "host-tools.mk","-j",format("%u",request.jobs),"SRCTOP=" SOURCE,"all",NULL);
  s=step("secureboot-staging-growth");args(s,PYTHON,SOURCE "/tools/test/secureboot/efi_staging_test.py",NULL);
  s=step("secureboot-vm");args(s,PYTHON,SOURCE "/tools/test/secureboot/run.py","--root",get("root"),"--work",get("output"),"--kernel",get("kernel"),"--qemu",get("qemu"),"--qemu-data",get("qemu-data"),"--vars-tool",get("uefi-vars-tool"),"--capsign",format("%s/capsign",request.native),"--loader",format("%s/stand/efi/loader_lua/loader_lua.efi",loader_objtop),"--startup-policy",SOURCE "/stand/lua/secureboot.lua",NULL);
  if(*get("test-generation-key"))args(s,"--generation-key",get("test-generation-key"),"--generation-certificate",get("test-generation-certificate"),NULL);
  if(*get("test-case"))args(s,"--case",get("test-case"),NULL);
  s=step("secureboot-evidence");args(s,PYTHON,SOURCE "/tools/test/secureboot/verify_evidence.py","--work",get("output"),NULL);
  if(!*get("test-case"))arg(s,"--require-complete");
  return;
 }
 bool tools=action("verify") || action("sign") || action("deploy") || action("bsdinstall") || action("media") || strcmp(get("signing"),"unsigned");
 if(tools){
  s=step("host-tools-directory");args(s,"mkdir","-p",request.native,NULL);
  s=step("host-tools");args(s,"make","-C",request.native,"-f",HELPERS "host-tools.mk","-j",format("%u",request.jobs),"SRCTOP=" SOURCE,NULL);
  if(action("media"))args(s,"all","kldxref",NULL);
 }
 if(action("verify") || action("sign")){
  s=step(request.action);args(s,"env",format("CAPSIGN=%s/capsign",request.native),"sh",action("sign")?HELPERS "sign-stage.sh":HELPERS "verify-stage.sh","-r",get("root"),action("sign")?"-k":"-p",action("sign")?get("key"):get("public-key"),NULL);
  if(action("sign") && !yes("relaxed-signatures"))arg(s,"-e");
  return;
 }
 if(action("deploy") || action("bsdinstall")){
  s=step(request.action);args(s,PYTHON,action("deploy")?HELPERS "deploy.py":HELPERS "installer.py","--repository",get("repository"),"--pkg-public-key",get("pkg-public-key"),"--public-key",get("public-key"),"--kernel",get("kernel"),"--capsign",format("%s/capsign",request.native),NULL);
  if(action("deploy")){
   args(s,"--generated",get("generated"),NULL);
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
  assignment(s,"HARDWARE_KLDXREF",format("%s/kldxref",request.native));assignment(s,"RELEASE_OBJDIR",get("output"));assignment(s,"TARGET",request.target);assignment(s,"TARGET_ARCH",request.arch);assignment(s,"KERNCONF",get("kernel"));assignment(s,"SRCCONF",get("src-conf"));assignment(s,"__MAKE_CONF",get("make-conf"));assignment(s,"PORTSDIR",get("ports"));assignment(s,"PKGBASE_SIGNED_REPOSITORY",get("repository"));assignment(s,"PKGBASE_REPO_PUBLIC_KEY",get("pkg-public-key"));assignment(s,"PKGBASE_CODE_PUBLIC_KEY",get("public-key"));args(s,"HARDWARE_PYTHON=" PYTHON,"NOPKGBASE=","NODISTSETS=yes","NOPKG=yes",NULL);
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
  s=backend.make("system-packages",true);
  /* The hardware stage refuses a profile that no longer selects the planned backend. */
  assignment(s,"HARDWARE_BACKEND",request.hardware?"native-ports":"kernel-identity-only");
  if(request.hardware)assignment(s,"PORTSDIR",get("ports"));
  assignment(s,"HARDWARE_PORT_LIST",get("hardware-profile"));
  if(request.hardware)assignment(s,"DISTDIR",get("distfiles"));
  arg(s,"REPODIR=" REPOSITORY);assignment(s,"PUBLISH_REPODIR",get("publish-repository"));
  /* Incremental compilation must not reuse signed installation output. */
  assignment(s,"WSTAGEDIR",format("%s/package-stage/world",request.run));
  assignment(s,"KSTAGEDIR",format("%s/package-stage/kernel",request.run));
  assignment(s,"SSTAGEDIR",format("%s/package-stage/source",request.run));
  if(*get("pkg-key")){assignment(s,"PKG_REPO_SIGNING_KEY",get("pkg-key"));assignment(s,"HARDWARE_SIGNING_KEY",get("pkg-key"));}
  if(*get("package-tool"))assignment(s,"PKG_CMD",get("package-tool"));
  if(*get("pkg-package")) {assignment(s,"PKGBASE_PKG_PACKAGE",get("pkg-package"));assignment(s,"PKGBASE_PKG_SHA256",get("pkg-package-sha256"));}
  if(*get("application-selection"))assignment(s,"APPLICATION_PACKAGE_SELECTION",get("application-selection"));
  assignment(s,"PUBLISH_ADVANCE_LATEST",yes("candidate-publication")?"no":"yes");
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
 if(!request.json){printf("build-bsd: action=%s cpus=%u kernel=%s production=%s bundle-signing-mode=%s target=%s/%s board=%s\n",request.action,request.jobs,get("kernel"),request.production?"yes":"no",get("signing"),request.target,request.arch,get("board"));puts(action("bazel-test")?(*get("bazel-inputs")?"qualification: scope=source-configured-qualification workspace-mode=explicit-inputs bazel=9-or-later runtime=selected-by-inputs system-backend=not-qualified":"qualification: scope=bazel-compile-comparison bazel=9-or-later module-resolution=offline-pinned-lockfile make-install-reference=requested runtime=not-performed system-backend=not-qualified"):firmware_test()?"security: verification-scope=firmware-only boot-verification=qemu-qualification-requested system-image-verification=not-performed root-protection-verification=not-performed":action("loader-build")?"security: verification-scope=trusted-builder-loader-compilation boot-verification=not-performed root-protection-verification=not-performed activation-authorized=no":action("inventory")?"security: verification-scope=package-payload-inventory input-authentication=not-performed activation-authorized=no":action("inventory-audit")?"security: verification-scope=selected-package-review-inventory input-authentication=not-performed program-compatibility-verification=not-performed authority-assigned=no":action("state-storage")?"security: verification-scope=offline-state-provisioning generation-authentication=not-performed activation-authorized=no":action("snapshot")?"security: verification-scope=signed-repository-snapshot consumer-verification=requested generation-authentication=not-performed activation-authorized=no":action("compose-config")?"security: verification-scope=explicit-configuration-composition input-authentication=not-performed service-policy-validation=not-performed activation-authorized=no":action("boot-observe")?"security: verification-scope=installed-boot-observation boot-verification=not-performed program-compatibility-verification=not-performed activation-authorized=no":action("boot-stage")?"security: verification-scope=boot-transport-makefs-input generation-authentication=not-performed boot-verification=not-performed activation-authorized=no":action("boot-check")?"security: verification-scope=collected-boot-transport-consistency generation-authentication=not-performed boot-verification=not-performed activation-authorized=no":action("image")?"security: verification-scope=trusted-builder-filesystem-image input-authentication=not-performed generation-authentication=not-performed boot-verification=not-performed activation-authorized=no":action("construct")?"security: verification-scope=trusted-builder-construction input-authentication=not-performed generation-authentication=not-performed activation-authorized=no":action("deploy")?"security: verification-scope=packages-bundles-and-filesystem generation-authentication=not-performed boot-verification=not-performed root-protection-verification=not-performed":action("reconcile")?"security: verification-scope=offline-filesystem-reconciliation input-authentication=not-performed boot-verification=not-performed root-protection-verification=not-performed":action("secureboot-test")?"security: verification-scope=uefi-and-loader boot-verification=qemu-qualification-requested system-image-verification=qemu-qualification-requested root-protection-verification=not-performed bootstrap-integrity-verification=kernel-dependent program-compatibility-verification=bounded-vm-fixture-requested":"security: verification-scope=system-bundles boot-verification=not-performed root-protection-verification=not-performed");
  /* A profile without ports publishes the kernel identity and no hardware packages. */
  if(request.packages && !request.hardware)puts("hardware: backend=kernel-identity-only hardware-packages=none hardware-compilation=not-performed");
  return;}
 printf("{\"schema\":\"org.5bsd.build-plan.v1\",\"record\":\"request\",\"action\":");json_string(request.action);
 const char *names[]={"target","target_arch","kernel","board","build_profile","signing","signing_scope","build_backend","hardware_backend","verification_scope","boot_verification","root_protection_verification","system_image_verification","bootstrap_integrity_verification","program_compatibility_verification"};
 const char *values[]={request.target,request.arch,get("kernel"),get("board"),get("build-profile"),get("signing"),"system-bundles",backend.name,(request.packages && !request.hardware)?"kernel-identity-only":"native-ports",action("bazel-test")?(*get("bazel-inputs")?(!strcmp(request.arch,"amd64")?"native-configured-qualification":"cross-configured-qualification"):"bazel-compile-comparison"):firmware_test()?"firmware-only":action("loader-build")?"trusted-builder-loader-compilation":action("inventory")?"package-payload-inventory":action("inventory-audit")?"selected-package-review-inventory":action("state-storage")?"offline-state-provisioning":action("snapshot")?"signed-repository-snapshot":action("compose-config")?"explicit-configuration-composition":action("boot-observe")?"installed-boot-observation":action("boot-stage")?"boot-transport-makefs-input":action("boot-check")?"collected-boot-transport-consistency":action("image")?"trusted-builder-filesystem-image":action("construct")?"trusted-builder-construction":action("deploy")?"packages-bundles-and-filesystem":action("reconcile")?"offline-filesystem-reconciliation":action("secureboot-test")?"uefi-and-loader":"system-bundles",action("secureboot-test")?"qemu-qualification-requested":"not-performed","not-performed",(action("secureboot-test") && !firmware_test())?"qemu-qualification-requested":"not-performed",(action("secureboot-test") && !firmware_test())?"kernel-dependent":"not-performed",(action("secureboot-test") && !firmware_test())?"bounded-vm-fixture-requested":"not-performed"};
 for(size_t i=0;i<nitems(names);i++){printf(",\"%s\":",names[i]);json_string(values[i]);}if(action("bazel-test"))printf(",\"make_install_reference\":\"%s\",\"bazel_minimum_major\":9,\"module_resolution\":\"%s\"",*get("bazel-inputs")?"not-performed":"requested",*get("bazel-inputs")?"native-inputs":"offline-pinned-lockfile");printf(",\"jobs\":%u}\n",request.jobs);
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
  /* Private orchestration files use 077; staged system trees need 022.
   * Signing-key creation independently enforces its private permissions. */
  umask(022);
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
 const char *names[]={"MAKEFLAGS","MFLAGS","MAKEOVERRIDES","MAKELEVEL","MAKEOBJDIRPREFIX","DESTDIR","DISTDIR","SRCCONF","SRC_ENV_CONF","__MAKE_CONF","ALLOW_DEBUG_MALLOC","TARGET","TARGET_ARCH","PKG_REPO_SIGNING_KEY","HARDWARE_SIGNING_KEY","KERNCONFDIR","REPODIR","PUBLISH_REPODIR","BASE_REPOSITORY","HARDWARE_REPO","COMPLETE_REPOSITORY","HARDWARE_ABI","HARDWARE_ABI_FILE","HARDWARE_BACKEND","WSTAGEDIR","KSTAGEDIR","SSTAGEDIR"};
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
