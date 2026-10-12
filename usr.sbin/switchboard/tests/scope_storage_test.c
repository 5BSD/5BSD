/* Exercise actual lifecycle and reclaim code with a small installed catalogue. */
#include "../lifecycle.c"
#include "../reclaim_publish.c"
#include <assert.h>
struct switchboard_state sd;
const char *switchboard_run_dir;
static unsigned installed = 2;
static uid_t owners[] = {1001, 1002};
static char tokens[2];
struct capbundle *bundle_registry_get(unsigned i) {
 return i < installed ? (struct capbundle *)&tokens[i] : NULL;
}
unsigned bundle_registry_count(void) { return installed; }
uid_t bundle_registry_owner_uid(unsigned i) { return owners[i]; }
const char *capbundle_name(const struct capbundle *b __unused) { return "Same.cap"; }
const char *capbundle_id(const struct capbundle *b __unused) { return "org.test.same"; }
unsigned capbundle_ngroups(const struct capbundle *b __unused) { return 1; }
const char *capbundle_group(const struct capbundle *b __unused, unsigned i __unused) { return "shared"; }
static bool exists(const char *subdir, const char *key) {
 char path[PATH_MAX];assert(snprintf(path,sizeof(path),"%s/%s/%s",switchboard_run_dir,subdir,key)<(int)sizeof(path));
 return access(path,F_OK)==0;
}
int main(void) {
 char dir[]="scope-storage.XXXXXX",ak[64],bk[64],ag[64],bg[64];
 assert(mkdtemp(dir));switchboard_run_dir=dir;
 struct svc_runtime *a=calloc(1,sizeof(*a)),*b=calloc(1,sizeof(*b));assert(a&&b);
 a->owner_uid=1001;b->owner_uid=1002;a->bundle_idx=0;b->bundle_idx=1;
 strlcpy(a->manifest.label,"Same/demo",sizeof(a->manifest.label));strlcpy(b->manifest.label,"Same/demo",sizeof(b->manifest.label));
 assert(svc_lifecycle_identity(a)==0&&svc_lifecycle_identity(b)==0);
 assert(memcmp(a->installation,b->installation,16)!=0);
 struct svc_new_client_msg am={0},bm={0};
 assert(svc_lifecycle_client(a,NULL,&am,1001)==0);assert(svc_lifecycle_client(b,NULL,&bm,1002)==0);
 assert(strcmp(am.container,bm.container)!=0&&strcmp(am.groups[0],bm.groups[0])!=0);
 assert(memcmp(am.generation,a->installation,16)==0);
 assert(sb_personal_storage_key("bundle",1001,"org.test.same",ak,sizeof(ak)));
 assert(sb_personal_storage_key("bundle",1002,"org.test.same",bk,sizeof(bk)));
 strlcpy(ag,am.groups[0],sizeof(ag));strlcpy(bg,bm.groups[0],sizeof(bg));
 assert(strncmp(am.container,ak,strlen(ak))==0);
 /* No running units: installed personal containers must still be preserved. */
 svc_reclaim_publish_live();assert(exists("live",ak)&&exists("live",bk));assert(exists("groups",ag)&&exists("groups",bg));
 installed=1;svc_reclaim_publish_live();assert(exists("live",ak)&&!exists("live",bk));assert(exists("groups",ag)&&!exists("groups",bg));
 /* Maximum UID and long unit labels fit without prefix truncation. */
 a->owner_uid=(uid_t)-2;
 memset(a->manifest.label,'x',sizeof(a->manifest.label)-1);
 a->manifest.label[sizeof(a->manifest.label)-1]='\0';
 assert(svc_lifecycle_client(a,NULL,&am,1001)==0);
 assert(strlen(am.container)==63);
 char prior[64];strlcpy(prior,am.container,sizeof(prior));
 a->manifest.label[sizeof(a->manifest.label)-2]='y';
 assert(svc_lifecycle_client(a,NULL,&am,1001)==0);
 assert(strcmp(prior,am.container)!=0);
 strlcpy(a->manifest.label,"Same/demo",sizeof(a->manifest.label));
 /* Global durable names and the legacy stable resource key are unchanged. */
 a->owner_uid=(uid_t)-1;assert(svc_lifecycle_client(a,NULL,&am,1001)==0);
 assert(strcmp(am.container,"Same/demo")==0&&strcmp(am.groups[0],"shared")==0);
 uint8_t legacy[16];svc_identity_from_label("Same/demo",legacy,NULL,0);assert(memcmp(legacy,am.generation,16)==0);
 /* Ambient sessions use the authenticated sender UID, not their shared label. */
 strlcpy(am.client_label,"session",sizeof(am.client_label));strlcpy(bm.client_label,"session",sizeof(bm.client_label));
 assert(svc_lifecycle_client(NULL,NULL,&am,1001)==0&&svc_lifecycle_client(NULL,NULL,&bm,1002)==0);
 assert(strcmp(am.resource_owner,bm.resource_owner)!=0);assert(am.container[0]=='\0'&&bm.container[0]=='\0');
 installed=0;svc_reclaim_publish_live();assert(!exists("live",ak)&&!exists("groups",ag));
 char p[PATH_MAX];snprintf(p,sizeof(p),"%s/live",dir);assert(rmdir(p)==0);snprintf(p,sizeof(p),"%s/groups",dir);assert(rmdir(p)==0);assert(rmdir(dir)==0);
 free(a);free(b);puts("PASS scoped resources, containers, groups, stopped installed membership, independent removal and global compatibility");return 0;
}
