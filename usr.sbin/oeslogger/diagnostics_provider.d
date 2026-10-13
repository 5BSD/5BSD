/* SPDX-License-Identifier: BSD-2-Clause */
provider oeslogger {
	probe event__handled(uint32_t a0, uint32_t a1);
	probe wait__done(int a0, int a1);
	probe dispatch__error(int a0, int a1);
};
