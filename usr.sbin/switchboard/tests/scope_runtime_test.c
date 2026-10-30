/* Actual private implementation functions; unrelated branches discarded by ld. */
#include "../naming.c"
#include "../domain.c"
#include "../reload.c"
#include "../on_demand.c"
#include "../sctl.c"
#include <assert.h>
#include "../management.c"
struct switchboard_state sd;
int switchboard_kq=-1;
int main(void) {
 int error;
 sd.services=calloc(2,sizeof(*sd.services));assert(sd.services);sd.nservices=2;
 struct svc_runtime *a=&sd.services[0],*b=&sd.services[1];
 a->owner_uid=1001;b->owner_uid=1002;
 strlcpy(a->manifest.label,"Same/demo",sizeof(a->manifest.label));
 strlcpy(b->manifest.label,"Same/demo",sizeof(b->manifest.label));
 a->manifest.nprovides=b->manifest.nprovides=1;
 strlcpy(a->manifest.provides[0],"org.test.endpoint",sizeof(a->manifest.provides[0]));
 strlcpy(b->manifest.provides[0],"org.test.endpoint",sizeof(b->manifest.provides[0]));
 assert(svc_by_label("Same/demo")==NULL);
 assert(svc_by_label_scoped("Same/demo",1001)==a);
 assert(svc_by_label_scoped("Same/demo",1002)==b);
 assert(naming_register("org.test.endpoint",a,false)==0);
 assert(naming_register("org.test.endpoint",b,false)==0);
 assert(naming_find_for_uid("org.test.endpoint",1001)->owner==a);
 assert(naming_find_for_uid("org.test.endpoint",1002)->owner==b);
 assert(naming_find_for_uid("org.test.endpoint",0)==NULL);
 assert(naming_find_for_uid("org.test.endpoint",(uid_t)-1)==NULL);
 assert(naming_find_for_uid("org.test.endpoint",1003)==NULL);
 assert(sctl_target("Same/demo",1001,false,false,&error)==a);
 assert(sctl_target("Same/demo",1002,false,false,&error)==b);
 assert(sctl_target("user:1002:Same/demo",1001,false,false,&error)==NULL);
 assert(sctl_target("user:1002:Same/demo",0,false,false,&error)==NULL);
 assert(sctl_target("user:1002:Same/demo",1001,true,false,&error)==b);
 assert(sctl_target("user:1002:Same/demo",1002,false,false,&error)==b);
 assert(sctl_target("user:999999999999999999999999999999:Same/demo",1001,true,false,&error)==NULL);
 assert(sctl_target("user:+1001:Same/demo",1001,true,false,&error)==NULL);
 assert(sctl_target("user:1001:",1001,true,false,&error)==NULL);
 struct pending_lookup p={0};
 strlcpy(p.provider_label,"Same/demo",sizeof(p.provider_label));
 p.provider_owner_uid=1001;p.provider_pid=-1;
 assert(pending_provider_matches(&p,a));assert(!pending_provider_matches(&p,b));
 strlcpy(p.requester_label,"Same/demo",sizeof(p.requester_label));
 p.requester_owner_uid=1001;
 a->state=b->state=SVC_STATE_STOPPED;
 assert(pending_launch_waiter(&p)==a);
 assert(naming_unregister("org.test.endpoint",a)==0);
 assert(naming_find_for_uid("org.test.endpoint",1001)==NULL);
 assert(naming_find_for_uid("org.test.endpoint",1002)->owner==b);
 assert(naming_unregister("org.test.endpoint",b)==0);
 free(sd.services);
 puts("PASS scoped runtime slots/endpoints, no root namespace bypass, explicit authorized management, independent pending activation and unregister");return 0;
}

/* These runtime-only tests have an empty installed catalogue. Unexpected
 * access beyond its count is a test failure; lazy loading is exercised by
 * the real-registry Secure Boot VM fixture. */
unsigned bundle_registry_count(void) { return (0); }
uid_t bundle_registry_owner_uid(unsigned index) { (void)index; abort(); }
struct capbundle *bundle_registry_get(unsigned index) { (void)index; abort(); }
void svc_slot_apply_bundle_policy(struct svc_runtime *svc, unsigned index)
{ (void)svc; (void)index; abort(); }
