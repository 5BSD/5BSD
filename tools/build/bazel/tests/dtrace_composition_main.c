/* SPDX-License-Identifier: BSD-2-Clause */
int composition_normal(int);
extern const char __bsd_dof_anchor_dtrace_composition;
static const void *volatile anchor;
#ifndef PIC_CONSUMER
int composition_static(void);
#endif
int main(void) {
 anchor = &__bsd_dof_anchor_dtrace_composition;
 if (anchor == 0) return 2;
#ifndef PIC_CONSUMER
 if (composition_static() != 42) return 1;
#endif
 return composition_normal(7) != 7;
}
