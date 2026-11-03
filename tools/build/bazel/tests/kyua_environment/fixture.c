/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int startup_environment;
static void observe_startup(void) __attribute__((constructor));
static void observe_startup(void) {
 const char *value = getenv("BSD_KYUA_DECLARED_ENV");
 const char *disable = getenv("DTRACE_DOF_INIT_DISABLE");
 startup_environment = value != NULL && strcmp(value, "before constructors") == 0 && disable != NULL && strcmp(disable, "1") == 0;
}
int main(void) {
 const char *workspace = getenv("TEST_WORKSPACE");
 puts("1..2");
 puts(startup_environment ? "ok 1 - declared environment reaches constructor" : "not ok 1 - declared environment missing at startup");
 puts(workspace != NULL && *workspace != '\0' ? "ok 2 - inherited unrelated environment survives" : "not ok 2 - inherited environment was removed");
 /* TAP result interpretation must not rely on this status. */
 return (0);
}
