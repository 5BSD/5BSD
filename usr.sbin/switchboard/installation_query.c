/* SPDX-License-Identifier: BSD-2-Clause */
#include <errno.h>
#include <channel.h>
#include "installation_query.h"
#include "switchboard_lifecycle.h"
#include "switchboard_svc_proto.h"
#include "installation_trace.h"

/* The control channel authenticates the caller; querying never creates an owner. */
int
svc_installation_query_reply(const char *path, struct channel_message *request)
{
	const struct svc_installation_query_req *req;
	struct svc_installation_query_reply reply = { 0 };
	struct sl_installation result;
	static struct sl_query_cache *cache;
	const char *label = "-";
	const uint8_t *generation = NULL;

	if (channel_message_fd_count(request) != 0 ||
	    channel_message_length(request) != sizeof(*req)) {
		reply.status = EINVAL;
		goto fail;
	}
	req = channel_message_data(request);
	if (req->op != SVC_OP_INSTALLATION_QUERY || req->flags != 0 ||
	    !sl_label_valid(req->label) ||
	    !sl_generation_valid(req->generation)) {
		reply.status = EINVAL;
		goto fail;
	}
	label = req->label;
	generation = req->generation;
	if (cache == NULL && (cache = sl_query_cache_create()) == NULL) {
		reply.status = errno;
		goto fail;
	}
	if (sl_query_cached(cache, path, req->label, req->generation, &result) == -1)
		reply.status = errno;
	else
		reply.state = result.state;
fail:
	svc_trace_installation("query", label, generation, reply.state, reply.status);
	/* Errors carry only status; a state is returned only after a completed read. */
	return (channel_send_reply(request, &(struct channel_outgoing)
	    CHANNEL_OUTGOING_INITIALIZER(&reply, reply.status == 0 ?
	    sizeof(reply) : sizeof(struct svc_reply))));
}
