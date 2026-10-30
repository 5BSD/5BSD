/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/avl.h>
#include <stddef.h>
#include <err.h>
struct item { int key; avl_node_t node; };
static int compare(const void *a, const void *b) {
    int x = ((const struct item *)a)->key, y = ((const struct item *)b)->key;
    return (x > y) - (x < y);
}
int main(void) {
    avl_tree_t tree;
    struct item nodes[257];
    avl_create(&tree, compare, sizeof(struct item), offsetof(struct item, node));
    for (int i = 0; i < 257; i++) {
        int k = (i * 37) % 257;
        nodes[k].key = k;
        avl_add(&tree, &nodes[k]);
    }
    if (avl_numnodes(&tree) != 257) errx(1, "insertion count");
    for (int i = 0; i < 257; i++) {
        struct item probe = { .key = i };
        if (avl_find(&tree, &probe, NULL) != &nodes[i]) errx(1, "lookup %d", i);
    }
    for (int i = 1; i < 257; i += 2) avl_remove(&tree, &nodes[i]);
    int expected = 0;
    for (struct item *p = avl_first(&tree); p; p = AVL_NEXT(&tree, p)) {
        if (p->key != expected) errx(1, "ordered traversal");
        expected += 2;
    }
    if (expected != 258 || avl_numnodes(&tree) != 129) errx(1, "removal count");
    void *cookie = NULL;
    int remaining = 0;
    while (avl_destroy_nodes(&tree, &cookie) != NULL) remaining++;
    if (remaining != 129 || !avl_is_empty(&tree)) errx(1, "destroy traversal");
    avl_destroy(&tree);
    return 0;
}
