/*
 * pfsync traffic - pfsync packets sent and received, and pflow flow
 * records exported (dtrace_pf(4)).
 */

pf:pfsync:packet:send
/* @bsdinstruments-predicate */
{
	@sent = count();
	@sent_bytes = sum(args[1]->m_pkthdr.len);
}

pf:pfsync:packet:input
{
	@received = count();
	@received_bytes = sum(args[0]->m_pkthdr.len);
}

pf:pflow:flow:export
{
	@flows = count();
}

dtrace:::END
{
	printa("pfsync packets sent      %@d\n", @sent);
	printa("pfsync bytes sent        %@d\n", @sent_bytes);
	printa("pfsync packets received  %@d\n", @received);
	printa("pfsync bytes received    %@d\n", @received_bytes);
	printa("pflow flows exported     %@d\n", @flows);
}
