/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdio.h>
#include "../scope_identity.h"
int main(void) {
 struct sb_install_scope global=sb_scope_from_registry_owner((uid_t)-1);
 struct sb_install_scope a=sb_scope_from_registry_owner(1001);
 struct sb_install_scope b=sb_scope_from_registry_owner(1002);
 struct sb_install_scope root=sb_scope_from_registry_owner(0);
 assert(!sb_scope_equal(a,b));
 assert(sb_scope_equal(a,sb_scope_from_registry_owner(1001)));
 assert(!sb_scope_equal(global,root));
 assert(!sb_scope_equal(global,a));
 assert(!sb_scope_names_conflict(a,b));
 assert(sb_scope_names_conflict(a,a));
 assert(sb_scope_names_conflict(global,a));
 assert(sb_scope_names_conflict(a,global));
 assert(sb_scope_names_conflict(global,global));
 /* No signature argument: unsigned and signed callers use same UID rule. */
 assert(sb_scope_personal_access(a,true,1001));
 assert(!sb_scope_personal_access(a,true,1002));
 assert(!sb_scope_personal_access(a,true,0));
 assert(!sb_scope_personal_access(a,false,1001));
 assert(!sb_scope_personal_access(a,true,(uid_t)-1));
 assert(!sb_scope_personal_access(global,true,1001));
 assert(sb_scope_personal_access(root,true,0));
 puts("16 scoped-identity contract assertions passed; production callers unchanged");
 return 0;
}
