/*
 * TCP connection lifespan — established to close duration.
 *
 * Tracks how long TCP connections live by timing from
 * connect/accept-established to state-change into CLOSED
 * or TIME_WAIT. Shows connection duration and IP payload bytes transferred.
 */

tcp:::connect-established,
tcp:::accept-established
/* @bsdinstruments-predicate */
{
	conn_start[arg1] = timestamp;
	conn_exec[arg1] = execname;
	conn_pid[arg1] = pid;
	conn_bytes_out[arg1] = 0;
	conn_bytes_in[arg1] = 0;
}

tcp:::send
/conn_start[arg1]/
{
	this->p = (uint8_t *)arg2;
	this->len = this->p == NULL ? 0 :
	    ((struct ip *)this->p)->ip_v == 4 ?
	    ntohs(((struct ip *)this->p)->ip_len) -
	    (((struct ip *)this->p)->ip_hl << 2) :
	    ntohs(((struct ip6_hdr *)this->p)->ip6_ctlun.ip6_un1.ip6_un1_plen);
	conn_bytes_out[arg1] += this->len;
}

tcp:::receive
/conn_start[arg1]/
{
	this->m = (struct mbuf *)arg2;
	this->len = this->m == NULL ? 0 :
	    ((struct ip *)this->m->m_data)->ip_v == 4 ?
	    ntohs(((struct ip *)this->m->m_data)->ip_len) -
	    (((struct ip *)this->m->m_data)->ip_hl << 2) :
	    ntohs(((struct ip6_hdr *)this->m->m_data)->
	    ip6_ctlun.ip6_un1.ip6_un1_plen);
	conn_bytes_in[arg1] += this->len;
}

tcp:::state-change
/conn_start[arg1] &&
 (((struct tcpcb *)arg3)->t_state == 0 ||
  ((struct tcpcb *)arg3)->t_state == 10)/
{
	this->ms = (timestamp - conn_start[arg1]) / 1000000;
	printf("%s[%d]: conn %dms tx=%d rx=%d\n",
	    conn_exec[arg1],
	    conn_pid[arg1],
	    this->ms,
	    conn_bytes_out[arg1],
	    conn_bytes_in[arg1]);
	@life[conn_exec[arg1]] = quantize(this->ms);
	conn_start[arg1] = 0;
	conn_exec[arg1] = 0;
	conn_pid[arg1] = 0;
	conn_bytes_out[arg1] = 0;
	conn_bytes_in[arg1] = 0;
}

dtrace:::END
{
    printf("\n--- TCP connection lifetime (ms) by process ---\n");
    printa(@life);
}
