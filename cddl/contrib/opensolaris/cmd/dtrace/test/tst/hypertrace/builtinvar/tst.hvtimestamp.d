/*
 * SPDX-License-Identifier: CDDL-1.0
 * A lone host virtual-time reference must enable its kernel accounting.
 */

#pragma D option quiet

BEGIN
{
	self->host_vtime = hvtimestamp;
	exit(0);
}
