/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>

#include "uart_backend_model.h"

ATF_TC_WITHOUT_HEAD(fifo_cursor_invariants);
ATF_TC_BODY(fifo_cursor_invariants, tc)
{

	ATF_CHECK(uart_rxfifo_state_valid(0, 0, 0, 1));
	ATF_CHECK(uart_rxfifo_state_valid(0, 0, 16, 16));
	ATF_CHECK(uart_rxfifo_state_valid(15, 1, 2, 16));
	ATF_CHECK(uart_rxfifo_state_valid(7, 3, 12, 16));

	ATF_CHECK(!uart_rxfifo_state_valid(0, 0, 0, 0));
	ATF_CHECK(!uart_rxfifo_state_valid(0, 0, 0, 17));
	ATF_CHECK(!uart_rxfifo_state_valid(16, 0, 0, 16));
	ATF_CHECK(!uart_rxfifo_state_valid(0, 16, 0, 16));
	ATF_CHECK(!uart_rxfifo_state_valid(0, 1, 16, 16));
	ATF_CHECK(!uart_rxfifo_state_valid(UINT32_MAX, 0, 1, 16));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fifo_cursor_invariants);
	return (atf_no_error());
}
