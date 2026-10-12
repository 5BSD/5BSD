/* Exercise actual private registry helpers without needing root-owned trees.
 * Files are real parsed bundles; only filesystem-owner scanning is bypassed.
 * Supplied UIDs model independently authenticated scanner owners. */
#include "../bundle_registry.c"
#include <assert.h>
const char *switchboard_bundle_dir_system;
const char *switchboard_bundle_dir_user;
const char *switchboard_users_dir;
struct switchboard_state sd;
static void file(const char *path,const char *text) {
 FILE *f=fopen(path,"w");assert(f);assert(fputs(text,f)>=0);assert(fclose(f)==0);
}
static struct capbundle *fixture(const char *root,const char *id,unsigned sequence,const char *provider) {
 char path[1024],text[1024],error[256];struct capbundle *b=NULL;
 assert(mkdir(root,0755)==0);
 snprintf(path,sizeof(path),"%s/Same.cap",root);assert(mkdir(path,0755)==0);
 snprintf(path,sizeof(path),"%s/Same.cap/Units",root);assert(mkdir(path,0755)==0);
 snprintf(path,sizeof(path),"%s/Same.cap/Units/demo.unit",root);assert(mkdir(path,0755)==0);
 snprintf(path,sizeof(path),"%s/Same.cap/Units/demo.unit/bin",root);assert(mkdir(path,0755)==0);
 snprintf(path,sizeof(path),"%s/Same.cap/Bundle.ucl",root);
 snprintf(text,sizeof(text),"schema=\"org.5bsd.capability-bundle\";bundle_id=\"%s\";version=\"1\";sequence=%u;author=\"t\";publisher=\"org.test\";units=[\"demo\"];",id,sequence);file(path,text);
 snprintf(path,sizeof(path),"%s/Same.cap/Units/demo.unit/Unit.ucl",root);
 snprintf(text,sizeof(text),"program=\"demo\";activation { ipc=[\"%s\"]; }",provider);file(path,text);
 snprintf(path,sizeof(path),"%s/Same.cap/Units/demo.unit/bin/demo",root);file(path,"#!/bin/sh\nexit 0\n");assert(chmod(path,0555)==0);
 snprintf(path,sizeof(path),"%s/Same.cap",root);
 if(capbundle_open_trusted(path,NULL,false,&b,error,sizeof(error))!=0){fprintf(stderr,"%s\n",error);abort();}return b;
}
int main(void) {
 disabled_ids=calloc(1,sizeof(*disabled_ids));assert(disabled_ids);
 disabled_ids[0]=strdup("user:1001:org.test.shared");assert(disabled_ids[0]);ndisabled=1;
 assert(bundle_is_disabled("org.test.shared",1001));
 assert(!bundle_is_disabled("org.test.shared",1002));
 assert(!bundle_is_disabled("org.test.shared",(uid_t)-1));
 disabled_set_clear();
 char dir[]="uid-scope-regression.XXXXXX";assert(mkdtemp(dir));assert(chdir(dir)==0);
 struct capbundle *a=fixture("u1001","org.test.shared",1,"org.test.endpoint");
 struct capbundle *b=fixture("u1002","org.test.shared",2,"org.test.endpoint");
 assert(registry_append(a,false,1001,-1)==0);assert(registry_append(b,false,1002,-1)==0);
 assert(nbundles==2);
 struct svc_manifest *m=calloc(1,sizeof(*m));assert(m);
 assert(registry_prune_user_conflicts(m)==0);free(m);assert(nbundles==2);
 assert(registry_build_indexes()==0);
 unsigned bi,si;
 assert(bundle_registry_lookup("org.test.endpoint",&bi,&si)==-1);
 assert(bundle_registry_lookup_for_uid("org.test.endpoint",1001,&bi,&si)==0 && bundles[bi].owner_uid==1001);
 assert(bundle_registry_lookup_for_uid("org.test.endpoint",1002,&bi,&si)==0 && bundles[bi].owner_uid==1002);
 assert(bundle_registry_lookup_for_uid("org.test.endpoint",1003,&bi,&si)==-1);
 assert(bundle_registry_lookup_for_uid("org.test.endpoint",0,&bi,&si)==-1);
 assert(bundle_registry_lookup_for_uid("org.test.endpoint",(uid_t)-1,&bi,&si)==-1);
 prev_bundles=bundles;nprev_bundles=nbundles;
 assert(previous_entry("/unrelated-user/Same.cap",false,1003)==-1);
 assert(previous_entry("/respelled-owner/Same.cap",false,1001)==0);
 assert(previous_entry("/respelled-owner/Same.cap",false,1002)==1);
 prev_bundles=NULL;nprev_bundles=0;
 puts("PASS same ID, labels, endpoints coexist; anonymous/root/unrelated UID cannot resolve personal names; stale fallback owner scoped");
 bundle_registry_teardown();
 a=fixture("upgrade1","org.test.upgrade",1,"org.test.one");
 b=fixture("upgrade2","org.test.upgrade",2,"org.test.two");
 assert(registry_append(a,false,1001,-1)==0);assert(registry_append(b,false,1001,-1)==0);
 assert(nbundles==1 && capbundle_sequence(bundles[0].bundle)==2);
 bundle_registry_teardown();
 a=fixture("global","org.test.global",1,"org.test.global.endpoint");
 b=fixture("shadow","org.test.global",9,"org.test.shadow");
 assert(registry_append(a,true,(uid_t)-1,-1)==0);assert(registry_append(b,false,1001,-1)==0);
 assert(nbundles==1 && bundles[0].system && nquarantined==1);
 assert(registry_build_indexes()==0);
 assert(bundle_registry_lookup_for_uid("org.test.global.endpoint",1002,&bi,&si)==0 && bundles[bi].system);
 bundle_registry_teardown();
 puts("PASS same-owner version selection and global anti-shadow rules preserved");
 printf("FIXTURES=%s\n",dir);return 0;
}
