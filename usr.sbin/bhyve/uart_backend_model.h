/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#ifndef _UART_BACKEND_MODEL_H_
#define	_UART_BACKEND_MODEL_H_

#include <stdbool.h>
#include <stdint.h>

#define	UART_RXFIFO_CAPACITY	16U

/* Validate the portable FIFO cursor/count representation before publish. */
static inline bool
uart_rxfifo_state_valid(uint32_t rindex, uint32_t windex, uint32_t num,
    uint32_t size)
{

	return (size >= 1 && size <= UART_RXFIFO_CAPACITY && rindex < size &&
	    windex < size && num <= size && windex == (rindex + num) % size);
}

#endif /* _UART_BACKEND_MODEL_H_ */
