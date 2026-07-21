/* Mock of bhyve config.h for the vsock device harness. */
#ifndef MOCK_CONFIG_H
#define MOCK_CONFIG_H
#include <stdbool.h>
typedef struct nvlist nvlist_t;
#ifndef NV_TYPE_NVLIST
#define NV_TYPE_NVLIST 5
#endif
const char *get_config_value_node(const nvlist_t *, const char *);
bool get_config_bool_node_default(const nvlist_t *, const char *, bool);
void set_config_value_node(nvlist_t *, const char *, const char *);
void set_config_bool_node(nvlist_t *, const char *, bool);
int pci_parse_legacy_config(nvlist_t *, const char *);
nvlist_t *create_relative_config_node(nvlist_t *, const char *);
nvlist_t *find_relative_config_node(nvlist_t *, const char *);
const char *nvlist_next(const nvlist_t *, int *, void **);
const nvlist_t *nvlist_get_nvlist(const nvlist_t *, const char *);
#endif
