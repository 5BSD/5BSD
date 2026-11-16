/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
provider moveio {
	probe rename__start();
	probe rename__done(int arg0, int arg1);
	probe fallback__start(int arg0);
	probe fallback__done(int arg0);
	probe child__start(int);
	probe child__done(int, int, int, int);
};
