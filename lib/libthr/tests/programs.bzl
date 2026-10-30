# SPDX-License-Identifier: BSD-2-Clause
# Native test-case inventory; sem is built for installed/isolated qualification.
PTHREAD_CASES = {
    "pthread_tryjoin": ["pthread_tryjoin"],
    "pthread_sigqueue": ["pthread_sigqueue"],
    "atfork": ["preinit_atfork", "basic_atfork", "multi_atfork"],
    "umtx_op": ["batching"],
    "barrier": ["barrier"],
    "fpu": ["fpu"],
    "equal": ["pthread_equal"],
    "once": ["once1", "once2", "once3"],
    "mutex": ["mutex1", "mutex2", "mutex3", "mutex4", "mutexattr1", "mutexattr2"],
    "rwlock": ["rwlock1", "rwlock_static"],
    "join": ["pthread_join"],
    "detach": ["pthread_detach"],
    "fork": ["fork"],
    "sigmask": ["upcalls_not_started", "before_threads", "respected_while_running", "incorrect_mask_bug"],
    "sleep": ["sleep1"],
    "preempt": ["preempt1"],
    "kill": ["simple"],
    "sigsuspend": ["sigsuspend"],
    "siglongjmp": ["siglongjmp1"],
    "swapcontext": ["swapcontext1"],
    "timedmutex": ["mutex1", "mutex2", "mutex3", "mutex4", "mutexattr1", "mutexattr2", "timedmutex1", "timedmutex2", "timedmutex3", "timedmutex4"],
    "cond": ["signal_delay_wait", "signal_before_unlock", "signal_before_unlock_static_init",
             "signal_wait_race", "cond_timedwait_race", "broadcast", "bogus_timedwaits",
             "destroy_busy", "destroy_after_cancel", "destroy_after_signal", "condattr"],
    "condwait": ["cond_wait_real", "cond_wait_mono", "cond_clockwait_real", "cond_clockwait_mono",
                 "cond_klockwait_real", "cond_klockwait_mono"],
}
PTHREAD_C_PROGRAMS = [name + "_test" for name in PTHREAD_CASES] + ["sem_test"]
PTHREAD_SHELL_PROGRAMS = ["atexit", "cancel", "exit", "resolv"]
