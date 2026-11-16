/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */

provider ffscheck {
	probe phase__start(int);
	probe phase__done(int);
};
