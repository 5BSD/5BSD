/* SPDX-License-Identifier: BSD-2-Clause */
/* Run only inside disposable Linux/FreeBSD reference guests. */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"PROC_PATH line %d: %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while (0)
static void checkpath(int fd, const char *want)
{
 char proc[64],got[PATH_MAX];
 snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
 ssize_t n=readlink(proc,got,sizeof(got)-1); CHECK(n>=0);
 got[n]=0;
 if (strcmp(got,want)) { fprintf(stderr,"PROC_PATH got <%s> want <%s>\n",got,want); exit(1); }
}
int main(int argc,char **argv)
{
 char root[PATH_MAX],a[PATH_MAX],b[PATH_MAX],moved[PATH_MAX],want[PATH_MAX];
 int fd,other=-1,pathflags=O_RDONLY; CHECK(argc==3); alarm(30);
 if (!strcmp(argv[2],"unprivileged")) { CHECK(setgid(65534)==0); CHECK(setuid(65534)==0); }
 CHECK(getcwd(root,sizeof(root))!=NULL);
 if (!strcmp(argv[1],"mountroot")) {
  /* The guest harness starts us at a ZFS, tmpfs, or nullfs mount root. */
  for (int i=0;i<2;i++) {
   fd=open(root,(i ? O_PATH : O_RDONLY)|O_DIRECTORY); CHECK(fd>=0);
   checkpath(fd,root);
   CHECK(close(fd)==0);
  }
  printf("PROC_PATH_PASS %s\n",argv[1]); return 0;
 }
 size_t len=strlen(root); CHECK(len+32<sizeof(root));
 strcpy(root+len,"/procpath.XXXXXX"); CHECK(mkdtemp(root)!=NULL);
 CHECK(chdir(root)==0 && mkdir("d",0700)==0);
 CHECK(snprintf(a,sizeof(a),"%s/d/a",root)>0);
 CHECK(snprintf(b,sizeof(b),"%s/d/b",root)>0);
 CHECK(snprintf(moved,sizeof(moved),"%s/d/moved",root)>0);
 if (!strcmp(argv[1],"deep_removed") || !strcmp(argv[1],"removed_then_rename")) {
  CHECK(mkdir("d/sub",0700)==0);
  CHECK(snprintf(a,sizeof(a),"%s/d/sub/a",root)>0);
 }
 fd=open(a,O_CREAT|O_RDWR|O_CLOEXEC,0600); CHECK(fd>=0);
 if (!strcmp(argv[1],"opath")) { CHECK(close(fd)==0); fd=open(a,O_PATH); CHECK(fd>=0); }
 if (!strcmp(argv[1],"simple")) checkpath(fd,a);
 else if (!strcmp(argv[1],"hardlink") || !strcmp(argv[1],"opath")) {
  CHECK(link(a,b)==0); other=open(b,O_RDONLY); CHECK(other>=0);
  checkpath(fd,a); checkpath(other,b);
 } else if (!strcmp(argv[1],"rename")) {
  CHECK(link(a,b)==0); other=open(b,O_RDONLY); CHECK(other>=0);
  CHECK(rename(a,moved)==0); checkpath(fd,moved); checkpath(other,b);
 } else if (!strcmp(argv[1],"unlink") || !strcmp(argv[1],"recreate") || !strcmp(argv[1],"procfd")) {
  CHECK(link(a,b)==0); CHECK(unlink(a)==0);
  CHECK(snprintf(want,sizeof(want),"%s (deleted)",a)>0); checkpath(fd,want);
  if (!strcmp(argv[1],"recreate")) {
   other=open(a,O_CREAT|O_RDWR,0600); CHECK(other>=0); checkpath(fd,want); checkpath(other,a);
  } else if (!strcmp(argv[1],"procfd")) {
   char proc[64]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
   other=open(proc,O_RDONLY); CHECK(other>=0); checkpath(other,want);
  }
 } else if (!strcmp(argv[1],"opath_events") || !strcmp(argv[1],"opath_dot_events")) {
  int notify=inotify_init1(IN_NONBLOCK|IN_CLOEXEC); CHECK(notify>=0);
  CHECK(inotify_add_watch(notify,"d",IN_OPEN|IN_CLOSE_NOWRITE)>=0);
  other=open(!strcmp(argv[1],"opath_dot_events") ? "d/." : a,O_PATH); CHECK(other>=0);
  CHECK(close(other)==0); other=-1;
  char events[4096]; CHECK(read(notify,events,sizeof(events))==-1 && errno==EAGAIN);
  CHECK(close(notify)==0);
 } else if (!strcmp(argv[1],"deep_removed") || !strcmp(argv[1],"removed_then_rename")) {
  CHECK(unlink(a)==0 && rmdir("d/sub")==0);
  if (!strcmp(argv[1],"removed_then_rename")) {
   CHECK(rename("d","moved")==0);
   CHECK(snprintf(want,sizeof(want),"%s/moved/sub/a (deleted)",root)>0);
   checkpath(fd,want); CHECK(rmdir("moved")==0);
  } else {
   CHECK(snprintf(want,sizeof(want),"%s (deleted)",a)>0); CHECK(rmdir("d")==0);
  }
  checkpath(fd,want);
 } else if (!strcmp(argv[1],"opath_search")) {
  CHECK(close(fd)==0); CHECK(chmod("d",0100)==0);
  fd=open("d/.",O_PATH|O_DIRECTORY); CHECK(fd>=0);
  CHECK(snprintf(want,sizeof(want),"%s/d",root)>0); checkpath(fd,want);
  CHECK(chmod("d",0700)==0 && unlink(a)==0 && rmdir("d")==0);
  CHECK(snprintf(want,sizeof(want),"%s/d (deleted)",root)>0); checkpath(fd,want);
 } else if (!strcmp(argv[1],"rename_race") || !strcmp(argv[1],"ancestor_race")) {
  int ancestor=!strcmp(argv[1],"ancestor_race");
  if (ancestor) CHECK(snprintf(moved,sizeof(moved),"%s/moved/a",root)>0);
  pid_t child=fork(); CHECK(child>=0);
  if (!child) {
   for (int i=0;i<500;i++) {
    CHECK(rename(ancestor ? "d" : a,ancestor ? "moved" : moved)==0);
    CHECK(rename(ancestor ? "moved" : moved,ancestor ? "d" : a)==0);
   }
   _exit(0);
  }
  char proc[64],got[PATH_MAX]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
  for (int i=0;i<2000;i++) {
   ssize_t n=readlink(proc,got,sizeof(got)-1); CHECK(n>=0); got[n]=0;
   if (strcmp(got,a) && strcmp(got,moved)) {
    fprintf(stderr,"PROC_PATH race got <%s>\n",got); exit(1);
   }
  }
  int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
  checkpath(fd,a);
 } else if (!strcmp(argv[1],"replace_parent_race")) {
  CHECK(mkdir("e",0700)==0);
  CHECK(snprintf(moved,sizeof(moved),"%s/e/a",root)>0);
  pid_t child=fork(); CHECK(child>=0);
  if (!child) {
   for (int i=0;i<100;i++) {
    CHECK(rename(a,moved)==0 && rmdir("d")==0 && mkdir("d",0700)==0);
    CHECK(rename(moved,a)==0 && rmdir("e")==0 && mkdir("e",0700)==0);
   }
   _exit(0);
  }
  char proc[64],got[PATH_MAX]; snprintf(proc,sizeof(proc),"/proc/self/fd/%d",fd);
  int bad=0;
  for (int i=0;i<2000;i++) {
   ssize_t n=readlink(proc,got,sizeof(got)-1);
   if (n<0) { fprintf(stderr,"PROC_PATH replace parent readlink errno=%d\n",errno); bad=1; break; }
   got[n]=0;
   if (strcmp(got,a) && strcmp(got,moved)) { fprintf(stderr,"PROC_PATH replace parent got <%s>\n",got); bad=1; break; }
  }
  int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
  CHECK(!bad); checkpath(fd,a);
 } else if (!strcmp(argv[1],"crossrename")) {
  CHECK(mkdir("e",0700)==0 && link(a,b)==0);
  other=open(b,O_RDONLY); CHECK(other>=0);
  CHECK(snprintf(moved,sizeof(moved),"%s/e/a",root)>0);
  CHECK(rename(a,moved)==0); checkpath(fd,moved); checkpath(other,b);
 } else if (!strcmp(argv[1],"ancestor_rename")) {
  CHECK(rename("d","moved")==0);
  CHECK(snprintf(want,sizeof(want),"%s/moved/a",root)>0); checkpath(fd,want);
 } else if (!strcmp(argv[1],"ancestor_removed")) {
  CHECK(unlink(a)==0 && rmdir("d")==0);
  CHECK(snprintf(want,sizeof(want),"%s (deleted)",a)>0); checkpath(fd,want);
 } else if (!strcmp(argv[1],"directory") || !strcmp(argv[1],"dot") || !strcmp(argv[1],"dotdot") || !strcmp(argv[1],"opath_directory")) {
  CHECK(close(fd)==0); CHECK(unlink(a)==0);
  const char *name="d";
  if (!strcmp(argv[1],"dot")) name="d/.";
  if (!strcmp(argv[1],"dotdot")) { CHECK(mkdir("d/sub",0700)==0); name="d/sub/.."; }
  if (!strcmp(argv[1],"opath_directory")) pathflags=O_PATH;
  fd=open(name,pathflags|O_DIRECTORY); CHECK(fd>=0);
  CHECK(snprintf(want,sizeof(want),"%s/d",root)>0); checkpath(fd,want);
  if (!strcmp(argv[1],"dotdot")) CHECK(rmdir("d/sub")==0);
  CHECK(rmdir("d")==0);
  CHECK(snprintf(want,sizeof(want),"%s/d (deleted)",root)>0); checkpath(fd,want);
 } else { fprintf(stderr,"unknown proc path case\n"); return 2; }
 if(other>=0) CHECK(close(other)==0);
 CHECK(close(fd)==0);
 unlink(a); unlink(b); unlink(moved); unlink("moved/a"); rmdir("d"); rmdir("moved"); rmdir("e");
 CHECK(chdir("..") == 0 && rmdir(root)==0);
 printf("PROC_PATH_PASS %s\n",argv[1]); return 0;
}
