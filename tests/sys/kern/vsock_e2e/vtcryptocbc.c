/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * vtcryptocbc -- 5BSD guest helper that proves the virtio_crypto(4) guest
 * driver registered with opencrypto(9) and that an AES-CBC request travels
 * through the emulated bhyve virtio-crypto device and back.
 *
 * The 5BSD guest base ships no cryptocheck(1) and no python3, so the Alpine
 * lane's gcrypto.py round-trip cannot run here.  This mirrors that helper's
 * cbc(aes) path in C, driving it through /dev/crypto (cryptodev(4)):
 *
 *   - open /dev/crypto;
 *   - CIOCFINDDEV with name "vtcrypto" -> the crypto framework returns the
 *     driver id (crid) of the virtio_crypto driver, which is proof that the
 *     guest driver called crypto_get_driverid() and is registered.  Matching
 *     by name (device_get_name() == "vtcrypto") also PINS the session to this
 *     driver specifically -- not aesni(4) or cryptosoft(4);
 *   - CIOCGSESSION2 for CRYPTO_AES_CBC with that crid, forcing the session onto
 *     the virtio_crypto provider (crypto_newsession() honours the crid);
 *   - CIOCCRYPT encrypt a fixed two-block plaintext with a fixed key and IV,
 *     assert the ciphertext differs from the plaintext, then CIOCCRYPT decrypt
 *     the ciphertext with the same session and IV and assert it recovers the
 *     plaintext byte for byte.  The decrypt(encrypt(x)) == x cycle is the live
 *     evidence that the data queue reached the device model and returned;
 *   - CIOCFSESSION to release the session.
 *
 * With a single "find" argument it stops after CIOCFINDDEV: that mode is the
 * registration-only probe used by the attach gate, independent of the data
 * path.  The device node defaults to /dev/crypto.
 *
 * Exit status is 0 only on success; any ioctl failure or mismatch is fatal.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <crypto/cryptodev.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	VTCRYPTOCBC_DRIVER	"vtcrypto"
#define	VTCRYPTOCBC_KEYLEN	16	/* AES-128 */
#define	VTCRYPTOCBC_IVLEN	16	/* one block */
#define	VTCRYPTOCBC_DATALEN	32	/* two blocks */

/* Fixed, deterministic key/IV/plaintext so a live run is reproducible. */
static const unsigned char vtcryptocbc_key[VTCRYPTOCBC_KEYLEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const unsigned char vtcryptocbc_iv[VTCRYPTOCBC_IVLEN] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
static const unsigned char vtcryptocbc_plaintext[VTCRYPTOCBC_DATALEN] = {
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

/*
 * Resolve the virtio_crypto driver id, proving opencrypto registration and
 * selecting that provider specifically.
 */
static int
vtcryptocbc_find(int fd)
{
	struct crypt_find_op find;

	memset(&find, 0, sizeof(find));
	find.crid = -1;
	strlcpy(find.name, VTCRYPTOCBC_DRIVER, sizeof(find.name));
	if (ioctl(fd, CIOCFINDDEV, &find) != 0)
		err(1, "CIOCFINDDEV %s (driver not registered with opencrypto)",
		    VTCRYPTOCBC_DRIVER);
	if (find.crid < 0)
		errx(1, "%s reported an invalid crid", VTCRYPTOCBC_DRIVER);
	return (find.crid);
}

int
main(int argc, char **argv)
{
	const char *node = "/dev/crypto";
	struct session2_op sop;
	struct crypt_op cop;
	unsigned char ciphertext[VTCRYPTOCBC_DATALEN];
	unsigned char recovered[VTCRYPTOCBC_DATALEN];
	int fd, crid, find_only;

	find_only = 0;
	if (argc > 1 && strcmp(argv[1], "find") == 0) {
		find_only = 1;
		argc--;
		argv++;
	}
	if (argc > 1)
		node = argv[1];

	fd = open(node, O_RDWR);
	if (fd < 0)
		err(1, "open %s", node);

	crid = vtcryptocbc_find(fd);

	if (find_only) {
		(void)close(fd);
		printf("vtcryptocbc: driver=%s crid=%d registered=yes\n",
		    VTCRYPTOCBC_DRIVER, crid);
		return (0);
	}

	/* Pin the AES-CBC session onto the virtio_crypto provider by crid. */
	memset(&sop, 0, sizeof(sop));
	sop.cipher = CRYPTO_AES_CBC;
	sop.keylen = VTCRYPTOCBC_KEYLEN;
	sop.key = vtcryptocbc_key;
	sop.ivlen = VTCRYPTOCBC_IVLEN;
	sop.crid = crid;
	if (ioctl(fd, CIOCGSESSION2, &sop) != 0)
		err(1, "CIOCGSESSION2 cbc(aes) on %s crid=%d", node, crid);

	/* Encrypt the fixed plaintext through the device. */
	memset(ciphertext, 0, sizeof(ciphertext));
	memset(&cop, 0, sizeof(cop));
	cop.ses = sop.ses;
	cop.op = COP_ENCRYPT;
	cop.len = VTCRYPTOCBC_DATALEN;
	cop.src = vtcryptocbc_plaintext;
	cop.dst = ciphertext;
	cop.iv = vtcryptocbc_iv;
	if (ioctl(fd, CIOCCRYPT, &cop) != 0)
		err(1, "CIOCCRYPT encrypt on %s", node);
	if (memcmp(ciphertext, vtcryptocbc_plaintext, sizeof(ciphertext)) == 0)
		errx(1, "ciphertext equals plaintext; device did not transform");

	/* Decrypt it back and require an exact round-trip. */
	memset(recovered, 0, sizeof(recovered));
	memset(&cop, 0, sizeof(cop));
	cop.ses = sop.ses;
	cop.op = COP_DECRYPT;
	cop.len = VTCRYPTOCBC_DATALEN;
	cop.src = ciphertext;
	cop.dst = recovered;
	cop.iv = vtcryptocbc_iv;
	if (ioctl(fd, CIOCCRYPT, &cop) != 0)
		err(1, "CIOCCRYPT decrypt on %s", node);
	if (memcmp(recovered, vtcryptocbc_plaintext, sizeof(recovered)) != 0)
		errx(1, "round-trip mismatch; device corrupted the payload");

	if (ioctl(fd, CIOCFSESSION, &sop.ses) != 0)
		err(1, "CIOCFSESSION on %s", node);
	(void)close(fd);

	printf("vtcryptocbc: driver=%s crid=%d registered=yes roundtrip=ok "
	    "bytes=%d\n", VTCRYPTOCBC_DRIVER, crid, VTCRYPTOCBC_DATALEN);
	return (0);
}
