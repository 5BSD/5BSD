/* SPDX-License-Identifier: BSD-2-Clause */
/* Exercise generated serializers with the selected SDK's XDR runtime. */
#include <string.h>
#include "crypt.h"

int
main(void)
{
	char buffer[256];
	char payload[] = "rpc fixture";
	desresp original = {0}, decoded = {0};
	XDR stream;
	u_int length;
	int failed;

	original.desbuf.desbuf_val = payload;
	original.desbuf.desbuf_len = sizeof(payload);
	original.stat = 42;
	for (unsigned i = 0; i < sizeof(original.des_ivec); i++)
		original.des_ivec[i] = i + 1;
	xdrmem_create(&stream, buffer, sizeof(buffer), XDR_ENCODE);
	if (!xdr_desresp(&stream, &original))
		return (1);
	length = xdr_getpos(&stream);
	xdr_destroy(&stream);
	xdrmem_create(&stream, buffer, length, XDR_DECODE);
	if (!xdr_desresp(&stream, &decoded))
		return (2);
	failed = decoded.stat != original.stat ||
	    decoded.desbuf.desbuf_len != sizeof(payload) ||
	    memcmp(decoded.desbuf.desbuf_val, payload, sizeof(payload)) != 0 ||
	    memcmp(decoded.des_ivec, original.des_ivec,
	    sizeof(original.des_ivec)) != 0;
	xdr_destroy(&stream);
	xdr_free((xdrproc_t)xdr_desresp, (char *)&decoded);
	return (failed ? 3 : 0);
}
