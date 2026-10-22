/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_ELF_H
#define DTRACED_ELF_H
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* Leave room for daemon framing inside its 64 MiB request limit. */
#define HYPERTRACE_ELF_MAX (64U * 1024U * 1024U - 4096U)
struct hypertrace_elf {
	unsigned char *data;
	size_t total;
	size_t received;
	uint32_t identifier;
};
static inline void
hypertrace_elf_reset(struct hypertrace_elf *state)
{
	free(state->data);
	memset(state, 0, sizeof(*state));
}
/* Zero accepts a fragment; complete is set only for a full final fragment. */
static inline int
hypertrace_elf_append(struct hypertrace_elf *state, uint32_t identifier,
    size_t total, const void *data, size_t length, int more, int *complete)
{
	*complete = 0;
	if (data == NULL || total == 0 || total > HYPERTRACE_ELF_MAX ||
	    length == 0 || length > total || (more != 0 && more != 1))
		goto invalid;
	if (state->data != NULL && (state->total != total ||
	    state->identifier != identifier))
		goto invalid;
	if (state->received > total || length > total - state->received ||
	    (more == 0 && length != total - state->received) ||
	    (more != 0 && length == total - state->received))
		goto invalid;
	if (state->data == NULL) {
		state->data = (unsigned char *)malloc(total);
		if (state->data == NULL)
			return (ENOMEM);
		state->total = total;
		state->identifier = identifier;
	}
	memcpy(state->data + state->received, data, length);
	state->received += length;
	*complete = more == 0;
	return (0);
invalid:
	hypertrace_elf_reset(state);
	return (EINVAL);
}
#endif
