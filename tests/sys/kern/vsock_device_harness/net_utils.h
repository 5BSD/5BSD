/* Minimal network utility interface for the VirtIO net device harness. */
#ifndef MOCK_NET_UTILS_H
#define MOCK_NET_UTILS_H

#include <sys/types.h>

struct pci_devinst;

int net_parsemac(const char *, uint8_t *);
void net_genmac(struct pci_devinst *, uint8_t *);
int net_parsemtu(const char *, unsigned long *);

#endif
