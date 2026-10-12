/* Parser-only: no RPC, filesystem edits or service changes. */
int switchboardctl_test_main(int, char **);
#define main switchboardctl_test_main
#include "../../switchboardctl/switchboardctl.c"
#undef main
#include <assert.h>
int main(void) {
 assert(valid_bundle_id("org.test.app"));
 assert(valid_bundle_id("user:1001:org.test.app"));
 assert(valid_bundle_id("user:0:org.test.app"));
 assert(!valid_bundle_id("user:01001:org.test.app"));
 assert(!valid_bundle_id("user:+1001:org.test.app"));
 assert(!valid_bundle_id("user:-1:org.test.app"));
 assert(!valid_bundle_id("user:4294967295:org.test.app"));
 assert(!valid_bundle_id("user:99999999999999999999999:org.test.app"));
 assert(!valid_bundle_id("user:1001:"));
 assert(!valid_bundle_id("user:1001:../escape"));
 puts("PASS canonical personal disable keys and invalid UID/path rejection");return 0;
}
