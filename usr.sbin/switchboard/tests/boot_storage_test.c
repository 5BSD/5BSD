/* SPDX-License-Identifier: BSD-2-Clause */
#include <atf-c.h>
#include "boot_storage.h"
ATF_TC_WITHOUT_HEAD(recipient_identity);
ATF_TC_BODY(recipient_identity, tc) {
    struct svc_manifest m = {0};
    (void)tc;
    strlcpy(m.label, "site.Store/provider", sizeof(m.label));
    m.management = SVC_MGMT_CORE;
    ATF_CHECK(boot_storage_recipient(&m, "site.Store", true, (uid_t)-1));
    ATF_CHECK(!boot_storage_recipient(&m, "site.Store", false, (uid_t)-1));
    ATF_CHECK(!boot_storage_recipient(&m, "site.Store", true, 0));
    ATF_CHECK(!boot_storage_recipient(&m, "site.Store", true, 1001));
    ATF_CHECK(!boot_storage_recipient(&m, "site.Other", true, (uid_t)-1));
    ATF_CHECK(!boot_storage_recipient(&m, NULL, true, (uid_t)-1));
    m.management = SVC_MGMT_SYSTEM;
    ATF_CHECK(!boot_storage_recipient(&m, "site.Store", true, (uid_t)-1));
    m.management = SVC_MGMT_CORE;
    strlcpy(m.label, "site.Store/provider/extra", sizeof(m.label));
    ATF_CHECK(!boot_storage_recipient(&m, "site.Store", true, (uid_t)-1));
}
ATF_TP_ADD_TCS(tp) { ATF_TP_ADD_TC(tp, recipient_identity); return atf_no_error(); }
