/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/list.h>
#include <sys/taskq.h>
#include <sys/kmem.h>
#include <libspl.h>
#include <err.h>
#include <stddef.h>
#include <stdio.h>

struct item { int value; list_node_t node; };
static void
complete(void *arg)
{
    int *value = arg;
    *value = 42;
}
int
main(void)
{
    list_t list;
    struct item a = { .value = 7 }, b = { .value = 35 };
    int results[32] = {0};
    libspl_init();
    list_create(&list, sizeof(struct item), offsetof(struct item, node));
    list_insert_tail(&list, &a);
    list_insert_tail(&list, &b);
    if (list_head(&list) != &a || list_next(&list, &a) != &b || list_tail(&list) != &b)
        errx(1, "list ordering");
    list_remove(&list, &a);
    list_remove(&list, &b);
    if (!list_is_empty(&list)) errx(1, "list removal");
    list_destroy(&list);
    taskq_t *queue = taskq_create("bazel-spl", 2, 0, 2, 32, TASKQ_PREPOPULATE);
    if (!queue) errx(1, "taskq_create");
    for (size_t i = 0; i < 32; i++)
        if (!taskq_dispatch(queue, complete, &results[i], TQ_SLEEP)) errx(1, "taskq_dispatch");
    taskq_wait(queue);
    for (size_t i = 0; i < 32; i++)
        if (results[i] != 42) errx(1, "task completion");
    taskq_destroy(queue);
    libspl_fini();
    puts("SPL list ordering and two-worker task queue completion passed");
    return (0);
}
