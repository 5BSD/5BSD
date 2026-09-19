/*
 * Workload and result summary for the capability service providers not covered
 * by the dedicated capsule, switchboard, logd, and component-ipc profiles.
 * Usage: bsdinstruments watch capability-services
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("Tracing capability services... Ctrl-C for summary.\n");
}

service_ambient*:::reg-result
{
	@ambient[arg0, arg1, arg2, arg3] = count();
}

notify*:::rpc
{
	@notify_rpc[execname, arg0, arg1] = count();
}

notify*:::publish
{
	@notify_publish[execname, arg2] = count();
	@notify_bytes[execname] = sum(arg1);
}

bsdnotify*:::publish
{
	@notify_route[arg3] = count();
	@notify_route_bytes = sum(arg2);
}

bsdnotify*:::deliver
{
	@notify_deliver[arg2] = count();
}

bsdnotify*:::session-admit
{
	@notify_admit[copyinstr(arg0), arg1, arg3] = count();
}

bsdnotify*:::tier-policy
{
	@notify_tier[arg1, copyinstr(arg2)] = count();
}

authagent*:::request-start
{
	self->authagent_start = timestamp;
}

authagent*:::request-done
{
	@authagent_requests[arg2, arg4, arg5] = count();
}

authagent*:::request-done
/self->authagent_start/
{
	@authagent_latency_ns[arg2, arg4] =
	    quantize(timestamp - self->authagent_start);
	self->authagent_start = 0;
}

authagent*:::elevate-start
{
	self->elevate_start = timestamp;
}

authagent*:::elevate-done
{
	@elevate_outcomes[copyinstr(arg5), arg3] = count();
	@elevate_names[copyinstr(arg2), arg3] = count();
}

authagent*:::elevate-done
/self->elevate_start/
{
	@elevate_latency_ns[copyinstr(arg5)] =
	    quantize(timestamp - self->elevate_start);
	self->elevate_start = 0;
}

authagent*:::ratelimit-block
{
	@elevate_ratelimited[arg0] = count();
}

authagent*:::policy-resolve
{
	@policy_grants[arg0, arg1, arg2, arg3, arg4] = count();
}

service_ambient*:::elevate-done
{
	@elevate_client[execname, arg1] = count();
}

switchboard*:::anoint-allow
{
	@anoint_allow[copyinstr(arg0), copyinstr(arg1)] = count();
}

switchboard*:::anoint-deny
{
	@anoint_deny[copyinstr(arg0), copyinstr(arg1), copyinstr(arg2)] =
	    count();
}

switchboard*:::mint-anoint
{
	@anoint_mint[arg0, arg1, arg2, arg3, arg4] = count();
}

localsysctl*:::request-start
{
	self->localsysctl_start = timestamp;
}

localsysctl*:::request-done
{
	@localsysctl_requests[arg1, arg3, arg4] = count();
	@localsysctl_bytes[arg1] = sum(arg2);
}

localsysctl*:::request-done
/self->localsysctl_start/
{
	@localsysctl_latency_ns[arg1, arg3] =
	    quantize(timestamp - self->localsysctl_start);
	self->localsysctl_start = 0;
}
localnetwork*:::request-done
{
	@network_requests[arg1, arg2] = count();
}

localnetwork*:::resolve-done
{
	@network_resolve[arg2] = count();
	@network_answers = sum(arg1);
}

localnetwork*:::connect-done
{
	@network_connect[arg3] = count();
}

localdevice*:::open
{
	@device_open[arg2, arg3] = count();
}

localdevice*:::list
{
	@device_list[arg3] = count();
	@device_entries = sum(arg2);
}

crypto*:::named-list
{
	@crypto_list[arg2] = count();
	@crypto_names = sum(arg1);
}

crypto*:::reclaim
{
	@crypto_reclaim = sum(arg1);
}

bsdextension*:::list
{
	@sysext_list[arg2] = count();
	@sysext_names = sum(arg1);
}

tzfsd*:::request-validate
{
	@tzfs_validate[arg0, arg4] = count();
}

tzfsd*:::request-grant
{
	@tzfs_grant[arg0, arg3] = count();
}

tzfsd*:::request-reply
{
	@tzfs_reply[arg0, arg1] = count();
}

warden*:::reclaim
{
	@warden_reclaim[arg1] = count();
}

dtrace:::END
{
	printf("\nambient discovery (private/create/send/ack):\n");
	printa("private=%d create_errno=%d send=%d ack=%d %@d\n", @ambient);
	printf("\nnotification client/router results:\n");
	printa("%-16s op=%d result=%d %@d\n", @notify_rpc);
	printa("%-16s result=%d publishes=%@d\n", @notify_publish);
	printa("%-16s bytes=%@d\n", @notify_bytes);
	printa("route-result=%d %@d\n", @notify_route);
	printa("deliver-result=%d %@d\n", @notify_deliver);
	printa("route-bytes=%@d\n", @notify_route_bytes);
	printa("admit %-28s tier=%d abi=%d %@d\n", @notify_admit);
	printa("tier=%d policy-source=%-14s %@d\n", @notify_tier);
	printf("\nauthentication agent results:\n");
	printa("kind=%d status=%d transport=%d requests=%@d\n",
	    @authagent_requests);
	printa("kind=%d status=%d latency-ns=%@d\n",
	    @authagent_latency_ns);
	printa("policy uid=%d count=%d all=%d admin=%d default=%d %@d\n",
	    @policy_grants);
	printf("\nelevation (anoint) results:\n");
	printa("stage=%-10s status=%d %@d\n", @elevate_outcomes);
	printa("name=%-32s status=%d %@d\n", @elevate_names);
	printa("stage=%-10s latency-ns=%@d\n", @elevate_latency_ns);
	printa("rate-limited uid=%d %@d\n", @elevate_ratelimited);
	printa("client %-16s errno=%d %@d\n", @elevate_client);
	printf("\nIPC anointment matches:\n");
	printa("allow %-32s requester=%-28s %@d\n", @anoint_allow);
	printa("deny  %-32s requester=%-28s missing=%s %@d\n", @anoint_deny);
	printa("mint uid=%d count=%d all=%d admin=%d status=%d %@d\n",
	    @anoint_mint);
	printf("\nsysctl provider results:\n");
	printa("op=%d status=%d transport=%d requests=%@d\n",
	    @localsysctl_requests);
	printa("op=%d bytes=%@d\n", @localsysctl_bytes);
	printa("op=%d status=%d latency-ns=%@d\n",
	    @localsysctl_latency_ns);
	printf("\nnetwork provider results:\n");
	printa("op=%d result=%d requests=%@d\n", @network_requests);
	printa("resolve-result=%d requests=%@d\n", @network_resolve);
	printa("connect-result=%d requests=%@d\n", @network_connect);
	printa("resolved-addresses=%@d\n", @network_answers);
	printf("\ndevice provider results:\n");
	printa("rights=0x%x error=%d opens=%@d\n", @device_open);
	printa("list-error=%d requests=%@d\n", @device_list);
	printa("listed-entries=%@d\n", @device_entries);
	printf("\ncrypto and extension results:\n");
	printa("crypto-list-result=%d requests=%@d\n", @crypto_list);
	printa("crypto-names=%@d\n", @crypto_names);
	printa("crypto-reclaimed=%@d\n", @crypto_reclaim);
	printa("sysext-list-result=%d requests=%@d\n", @sysext_list);
	printa("sysext-names=%@d\n", @sysext_names);
	printf("\nstorage and namespace results:\n");
	printa("tzfs-op=%d valid=%d requests=%@d\n", @tzfs_validate);
	printa("tzfs-op=%d error=%d grants=%@d\n", @tzfs_grant);
	printa("tzfs-op=%d status=%d replies=%@d\n", @tzfs_reply);
	printa("warden-reclaimed=%d events=%@d\n", @warden_reclaim);
}
