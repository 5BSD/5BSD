/* SPDX-License-Identifier: BSD-2-Clause */
#include <security/pam_appl.h>
#include <security/openpam.h>
#include <assert.h>
static int conv(int n,const struct pam_message **m,struct pam_response **r,void *d) {
 (void)n;(void)m;(void)r;(void)d;return PAM_CONV_ERR;
}
int main(int argc,char **argv) {
 pam_handle_t *p=NULL; struct pam_conv c={conv,NULL}; assert(argc==2);
 assert(openpam_set_feature(OPENPAM_VERIFY_POLICY_FILE,0)==PAM_SUCCESS);
 assert(openpam_set_feature(OPENPAM_RESTRICT_SERVICE_NAME,0)==PAM_SUCCESS);
 assert(pam_start(argv[1],"trace-test",&c,&p)==PAM_SUCCESS);
 int r=pam_authenticate(p,0); assert(r!=PAM_SUCCESS); assert(pam_end(p,r)==PAM_SUCCESS);
 return 0;
}
