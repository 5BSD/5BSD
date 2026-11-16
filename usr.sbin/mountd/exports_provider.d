/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */

provider exports {
	probe reload__start(int);
	probe reload__done(int);
};
