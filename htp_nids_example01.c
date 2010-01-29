#include <stdio.h>
#include <assert.h> 
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <nids.h>
#include <htp/htp.h>

struct ht_sniff_cfg {
    htp_cfg_t *hcfg;
    char *iface;
    char *filter;
};

struct ht_sniff_cfg *cfg;

int
loghdr_cb(htp_connp_t *connp)
{
    char *method, 
	 *host, 
	 *agent,
	 *proto,
	 *referer,
	 *uri;
    htp_tx_t *tx;
    htp_header_t *hdr;

    host = method = proto = 
	referer = uri = agent = NULL;

    list_iterator_reset(connp->conn->transactions);
    tx    = list_iterator_next(connp->conn->transactions);

    uri     = bstr_tocstr(tx->request_uri);
    proto   = bstr_tocstr(tx->request_protocol);
    method  = bstr_tocstr(tx->request_method);
    
    if ((hdr = table_getc(tx->request_headers, "host")))
	host = bstr_tocstr(hdr->value);

    if ((hdr = table_getc(tx->request_headers, "referer")))
	referer = bstr_tocstr(hdr->value);

    if ((hdr = table_getc(tx->request_headers, "user-agent")))
	agent = bstr_tocstr(hdr->value);

    printf("%s %s:%d \"%s http://%s%s %s\" \"%s\" \"%s\"\n", 
	    connp->conn->remote_addr, 
	    connp->conn->local_addr, 
	    connp->conn->local_port,
	    method, 
	    host?host:connp->conn->remote_addr, 
	    uri?uri:"", 
	    proto,
	    referer?referer:"-",
	    agent?agent:"-");
    
    if (method) free(method);
    if (proto) free(proto);
    if (uri) free(uri);
    if (referer) free(referer);
    if (agent) free(agent);
    if (host) free(host);

    return 0;
}


void
ht_sniff_cb(struct tcp_stream *a_tcp, void **pkt)
{
    htp_connp_t *connp;
    struct timeval tv;
    struct half_stream *hlf;
    char *srcaddr, *dstaddr;

    gettimeofday(&tv, NULL);

    switch(a_tcp->nids_state)
    {
	case NIDS_JUST_EST:
	    srcaddr = strdup((char *)inet_ntoa(*(struct in_addr *)
		    &a_tcp->addr.saddr));
	    dstaddr = strdup((char *)inet_ntoa(*(struct in_addr *)
		    &a_tcp->addr.daddr));

	    /* initialize our connection pointer */

	    assert((connp = htp_connp_create(cfg->hcfg)));

	    htp_connp_open(connp, srcaddr, 432, dstaddr, 80, tv.tv_usec); 

	    free(srcaddr);
	    free(dstaddr);

	    /* tell libnids to only watch the client data */
	    a_tcp->server.collect = 1;
	    a_tcp->user = connp;
	    break;
	case NIDS_TIMED_OUT:
	case NIDS_CLOSE:
	case NIDS_EXITING:
	case NIDS_RESET:
	    if ((connp = a_tcp->user))
	    {
		htp_connp_close(connp, tv.tv_usec);
		htp_connp_destroy_all(connp);
	    }
	    break;
	case NIDS_DATA:
	    if (!(connp = a_tcp->user))
		/* yuck */
		break;

	    if (!(hlf = &a_tcp->server))
		/* yuck2 */
		break;

	    if (htp_connp_req_data(connp, tv.tv_usec,
			hlf->data, hlf->count) == HTP_ERROR)
		break;

	    nids_discard(a_tcp, hlf->count);
	    break;
	default:
	    /* yuck */
	    break;
    }

}
	    
int
parse_args(struct ht_sniff_cfg *cfg, 
	int argc, char **argv)
{
    extern char *optarg;
    extern int   optind,
	         opterr,
		 optopt;
    int          c;

    static char *help = 
	"Options: \n"
	" -h:         Derr...\n"
	" -i <iface>: Interface to sniff\n"
	" -l <fmt>  : Log format\n"
	" -f <bpf>:   BPF Filter\n";

    cfg->iface  = "eth0";
    cfg->filter = "tcp port 80";

    while((c = getopt(argc, argv, "hi:f:l:")) != -1)
    {
	switch(c)
	{
	    case 'i':
		cfg->iface  = optarg;
		break;
	    case 'f':
		cfg->filter = optarg;
		break;
	    case 'h':
	    default:
		printf("Usage: %s [opts\n%s",
			argv[0], help);
		exit(1);
	}
    }

    return 0;
}

void
ht_nids_init(struct ht_sniff_cfg *cfg)
{
    struct nids_chksum_ctl ctl;

    /* turn off the libnids scanning stuff */
    nids_params.scan_num_hosts  = 0;
    nids_params.tcp_workarounds = 1;
    nids_params.pcap_filter     = cfg->filter;
    nids_params.device          = cfg->iface;

    assert(nids_init());

    /* we want to turn off the checksum checking since
       many new interfaces include checksum offloading */
    ctl.netaddr = 0;
    ctl.mask    = 0;
    ctl.action  = NIDS_DONT_CHKSUM;

    nids_register_chksum_ctl(&ctl, 1);
    nids_register_tcp(ht_sniff_cb);
}

void
ht_sniff_init(struct ht_sniff_cfg *cfg)
{
    assert((cfg->hcfg = htp_config_create()));

    htp_config_set_server_personality(cfg->hcfg,
	    HTP_SERVER_IDS);
    htp_config_register_request_headers(cfg->hcfg, 
	    loghdr_cb);
}

int main(int argc, char **argv)
{
    if (!(cfg = calloc(sizeof(struct ht_sniff_cfg), 1)))
	perror(strerror(errno));
    
    if (!(cfg->hcfg = htp_config_create()))
	perror(strerror(errno));

    parse_args(cfg, argc, argv);
    ht_nids_init(cfg);
    ht_sniff_init(cfg);

    nids_run();

    return 0;
}

	



