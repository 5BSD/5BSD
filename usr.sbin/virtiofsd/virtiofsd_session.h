/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VIRTIOFSD_SESSION_H_
#define	_VIRTIOFSD_SESSION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	VIRTIOFSD_SESSION_STATE_HEADER_SIZE	32U
#define	VIRTIOFSD_SESSION_STATE_SIZE	VIRTIOFSD_SESSION_STATE_HEADER_SIZE

struct virtiofsd_export;
struct virtiofsd_session;

int	virtiofsd_session_create(struct virtiofsd_export *, size_t, size_t,
	    struct virtiofsd_session **);
void	virtiofsd_session_destroy(struct virtiofsd_session *);
int	virtiofsd_session_execute(struct virtiofsd_session *, const void *,
	    size_t, void *, size_t, size_t *, bool *);
int	virtiofsd_session_discard_result(struct virtiofsd_session *,
	    const void *, size_t, const void *, size_t);
int	virtiofsd_session_request_expects_reply(struct virtiofsd_session *,
	    const void *, size_t, bool *);
int	virtiofsd_session_checkpoint(struct virtiofsd_session *,
	    uint8_t [VIRTIOFSD_SESSION_STATE_SIZE]);
int	virtiofsd_session_checkpoint_size(struct virtiofsd_session *,
	    size_t *);
int	virtiofsd_session_checkpoint_write(struct virtiofsd_session *,
	    void *, size_t, size_t *);
int	virtiofsd_session_restore(struct virtiofsd_session *, const void *,
	    size_t);

#endif
