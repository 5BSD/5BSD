/* SPDX-License-Identifier: BSD-2-Clause */
/* Bounded DER framing for the certificate TBS hash used by UEFI dbx. */
#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

#include "x509_tbs.h"

static int
sequence(const unsigned char *data, size_t size, size_t *header, size_t *total)
{
	size_t length, bytes, pos;

	if (size < 2 || data[0] != 0x30)
		return (-1);
	length = data[1];
	pos = 2;
	if ((length & 0x80) != 0) {
		bytes = length & 0x7f;
		if (bytes == 0 || bytes > sizeof(length) || bytes > size - pos ||
		    data[pos] == 0)
			return (-1);
		length = 0;
		while (bytes-- != 0)
			length = (length << 8) | data[pos++];
		if (length < 128)
			return (-1);
	}
	if (length > size - pos)
		return (-1);
	*header = pos;
	*total = pos + length;
	return (0);
}

const unsigned char *
ve_x509_tbs(const unsigned char *cert, size_t size, size_t *tbs_size)
{
	size_t header, total, inner_header, inner_total;

	*tbs_size = 0;
	if (cert == NULL || sequence(cert, size, &header, &total) != 0 ||
	    total != size || sequence(cert + header, total - header,
	    &inner_header, &inner_total) != 0)
		return (NULL);
	/* UEFI hashes the complete DER TBSCertificate, including its header. */
	*tbs_size = inner_total;
	return (cert + header);
}
