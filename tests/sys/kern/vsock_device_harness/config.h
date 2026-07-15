/* Mock of bhyve config.h for the vsock device harness. */
#ifndef MOCK_CONFIG_H
#define MOCK_CONFIG_H
typedef struct nvlist nvlist_t;
const char *get_config_value_node(const nvlist_t *, const char *);
void set_config_value_node(nvlist_t *, const char *, const char *);
int pci_parse_legacy_config(nvlist_t *, const char *);
#endif
