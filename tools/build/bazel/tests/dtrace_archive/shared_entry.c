/* SPDX-License-Identifier: BSD-2-Clause */
extern int shared_initialization_ok(void);
extern int shared_first(int);
extern int shared_second(int);
/* Forces archive extraction even when the only caller is later discarded. */
int discarded_shared_caller(void)
{
    return shared_first(1) + shared_second(2);
}
int fixture_run(void)
{
    if (!shared_initialization_ok())
        return 1;
#if TEST_SELECTION == 1
    return shared_first(41) != 42;
#elif TEST_SELECTION == 2
    return shared_second(40) != 42;
#elif TEST_SELECTION == 3
    return shared_first(41) != 42 || shared_second(40) != 42;
#else
    return 0;
#endif
}
