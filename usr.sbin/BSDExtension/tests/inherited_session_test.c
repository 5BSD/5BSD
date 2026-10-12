/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

/* Include the real client to force its otherwise opaque lock into the
 * inherited locked state without depending on provider timing. */
#include "extensioncmp.c"

static void
check_inherited(bool process_descriptor, bool failed)
{
    struct extensioncmp_session *session;
    int pd = -1, status, loaded;
    pid_t child;

    session = calloc(1, sizeof(*session));
    ATF_REQUIRE(session != NULL);
    session->creator = getpid();
    session->owner = failed ? 0 : getpid();
    session->failed = failed ? EPIPE : 0;
    ATF_REQUIRE_EQ(0, pthread_mutex_init(&session->lock, NULL));
    ATF_REQUIRE_EQ(0, pthread_mutex_lock(&session->lock));
    child = process_descriptor ? pdfork(&pd, 0) : fork();
    ATF_REQUIRE(child >= 0);
    if (child == 0) {
        alarm(3);
        if (extensioncmp_stat(session, "kernel", &loaded) != -1 ||
            errno != ECHILD)
            _exit(1);
        extensioncmp_session_close(session);
        _exit(0);
    }
    ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
    ATF_REQUIRE(WIFEXITED(status));
    ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
    ATF_REQUIRE_EQ(0, pthread_mutex_unlock(&session->lock));
    extensioncmp_session_close(session);
    if (pd >= 0)
        close(pd);
}

ATF_TC_WITHOUT_HEAD(inherited_locked_session);
ATF_TC_BODY(inherited_locked_session, tc)
{
    (void)tc;
    check_inherited(false, false);
    check_inherited(false, true);
    check_inherited(true, false);
    check_inherited(true, true);
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, inherited_locked_session);
    return (atf_no_error());
}
