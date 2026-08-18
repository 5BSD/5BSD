/* Print every SCTP send and receive event with IP payload length. */

sctp:::send
/* @bsdinstruments-predicate */
{
	this->p = (uint8_t *)arg2;
	this->len = this->p == NULL ? 0 :
	    ((struct ip *)this->p)->ip_v == 4 ?
	    ntohs(((struct ip *)this->p)->ip_len) -
	    (((struct ip *)this->p)->ip_hl << 2) :
	    ntohs(((struct ip6_hdr *)this->p)->ip6_ctlun.ip6_un1.ip6_un1_plen);
	printf("%s[%d]: sctp send %d bytes\n", execname, pid, this->len);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

sctp:::receive
/* @bsdinstruments-predicate */
{
	this->m = (struct mbuf *)arg2;
	this->len = this->m == NULL ? 0 :
	    ((struct ip *)this->m->m_data)->ip_v == 4 ?
	    ntohs(((struct ip *)this->m->m_data)->ip_len) -
	    (((struct ip *)this->m->m_data)->ip_hl << 2) :
	    ntohs(((struct ip6_hdr *)this->m->m_data)->
	    ip6_ctlun.ip6_un1.ip6_un1_plen);
	printf("%s[%d]: sctp recv %d bytes\n", execname, pid, this->len);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
