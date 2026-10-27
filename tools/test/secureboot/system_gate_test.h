/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SECUREBOOT_SYSTEM_GATE_TEST_H
#define SECUREBOOT_SYSTEM_GATE_TEST_H
int system_gate_test(void);
int system_gate_denial_test(void);
int system_gate_reauthorize_test(int);
int system_gate_capsule_test(void);
#endif
