/* SPDX-License-Identifier: BSD-2-Clause */
provider btaudio {
	probe command__start(int fd, uint8_t command, uint8_t transaction);
	probe command__done(int fd, uint8_t command, uint8_t transaction, int result);
};
