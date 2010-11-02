/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file vpn/gnunet-daemon-vpn.c
 * @brief 
 * @author Philipp Tölke
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet-vpn-helper-p.h"
#include "gnunet-vpn-packet.h"
#include "gnunet-vpn-pretty-print.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet-service-dns-p.h"
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "block_dns.h"

/**
 * Final status code.
 */
static int ret;

/**
 * The scheduler to use throughout the daemon
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * The configuration to use
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * PipeHandle to receive data from the helper
 */
static struct GNUNET_DISK_PipeHandle* helper_in;

/**
 * PipeHandle to send data to the helper
 */
static struct GNUNET_DISK_PipeHandle* helper_out;

/**
 * FileHandle to receive data from the helper
 */
static const struct GNUNET_DISK_FileHandle* fh_from_helper;

/**
 * FileHandle to send data to the helper
 */
static const struct GNUNET_DISK_FileHandle* fh_to_helper;

/**
 * The Message-Tokenizer that tokenizes the messages comming from the helper
 */
static struct GNUNET_SERVER_MessageStreamTokenizer* mst;

/**
 * The connection to the service-dns
 */
static struct GNUNET_CLIENT_Connection *dns_connection;

/**
 * A flag to show that the service-dns has to rehijack the outbound dns-packets
 *
 * This gets set when the helper restarts as the routing-tables are flushed when
 * the interface vanishes.
 */
static unsigned char restart_hijack;

/**
 * The process id of the helper
 */
static pid_t helper_pid;

/**
 * a list of outgoing dns-query-packets
 */
static struct query_packet_list *head;

/**
 * The last element of the list of outgoing dns-query-packets
 */
static struct query_packet_list *tail;

/**
 * A list of processed dns-responses.
 *
 * "processed" means that the packet is complete and can be sent out via udp
 * directly
 */
static struct answer_packet_list *answer_proc_head;

/**
 * The last element of the list of processed dns-responses.
 */
static struct answer_packet_list *answer_proc_tail;

static void helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx);
static void dns_answer_handler(void* cls, const struct GNUNET_MessageHeader *msg);

/**
 * Callback called by notify_transmit_ready; sends dns-queries or rehijack-messages
 * to the service-dns
 */
static size_t
send_query(void* cls, size_t size, void* buf) {
    size_t len;
    /*
     * Send the rehijack-message
     */
    if (restart_hijack == 1)
      {
	restart_hijack = 0;
	/*
 	 * The message is just a header
	 */
	GNUNET_assert(sizeof(struct GNUNET_MessageHeader) >= size);
	struct GNUNET_MessageHeader* hdr = buf;
	len = sizeof(struct GNUNET_MessageHeader);
	hdr->size = htons(len);
	hdr->type = htons(GNUNET_MESSAGE_TYPE_REHIJACK);
      }
    else
      {
	struct query_packet_list* query = head;
	len = ntohs(query->pkt.hdr.size);

	GNUNET_assert(len <= size);

	memcpy(buf, &query->pkt.hdr, len);

	GNUNET_CONTAINER_DLL_remove (head, tail, query);

	GNUNET_free(query);
      }

    /*
     * Check whether more data is to be sent
     */
    if (head != NULL || restart_hijack == 1)
      {
	GNUNET_CLIENT_notify_transmit_ready(dns_connection, ntohs(head->pkt.hdr.size), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);
      }

    return len;
}

/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
    GNUNET_assert (0 != (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN));

    /* stop the helper */
    PLIBC_KILL(helper_pid, SIGTERM);
    GNUNET_OS_process_wait(helper_pid);

    /* close the connection to the service-dns */
    if (dns_connection != NULL)
      {
	GNUNET_CLIENT_disconnect (dns_connection, GNUNET_NO);
	dns_connection = NULL;
      }
}

/**
 * Start the helper-process
 */
static void
start_helper_and_schedule(void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc) {
    if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      return;

    helper_in = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO);
    helper_out = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_NO, GNUNET_YES);

    if (helper_in == NULL || helper_out == NULL) return;

    helper_pid = GNUNET_OS_start_process(helper_in, helper_out, "gnunet-helper-vpn", "gnunet-helper-vpn", NULL);

    fh_from_helper = GNUNET_DISK_pipe_handle (helper_out, GNUNET_DISK_PIPE_END_READ);
    fh_to_helper = GNUNET_DISK_pipe_handle (helper_in, GNUNET_DISK_PIPE_END_WRITE);

    GNUNET_DISK_pipe_close_end(helper_out, GNUNET_DISK_PIPE_END_WRITE);
    GNUNET_DISK_pipe_close_end(helper_in, GNUNET_DISK_PIPE_END_READ);

    GNUNET_SCHEDULER_add_read_file (sched, GNUNET_TIME_UNIT_FOREVER_REL, fh_from_helper, &helper_read, NULL);
}

/**
 * Restart the helper-process
 */
static void
restart_helper(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
    // Kill the helper
    PLIBC_KILL(helper_pid, SIGKILL);
    GNUNET_OS_process_wait(helper_pid);

    /* Tell the dns-service to rehijack the dns-port
     * The routing-table gets flushed if an interface disappears.
     */
    restart_hijack = 1;
    GNUNET_CLIENT_notify_transmit_ready(dns_connection, sizeof(struct GNUNET_MessageHeader), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);

    GNUNET_DISK_pipe_close(helper_in);
    GNUNET_DISK_pipe_close(helper_out);

    /* Restart the helper */
    GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_UNIT_SECONDS, start_helper_and_schedule, NULL);
}

/**
 * Read from the helper-process
 */
static void
helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx) {
    /* no message can be bigger then 64k */
    char buf[65535];

    if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
      return;

    int t = GNUNET_DISK_file_read(fh_from_helper, &buf, 65535);

    /* On read-error, restart the helper */
    if (t<=0) {
	GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Read error for header from vpn-helper: %m\n");
	GNUNET_SCHEDULER_add_now(sched, restart_helper, cls);
	return;
    }

    /* FIXME */ GNUNET_SERVER_mst_receive(mst, NULL, buf, t, 0, 0);

    GNUNET_SCHEDULER_add_read_file (sched, GNUNET_TIME_UNIT_FOREVER_REL, fh_from_helper, &helper_read, NULL);
}

/**
 * Calculate the checksum of an IPv4-Header
 */
static uint16_t
calculate_ip_checksum(uint16_t* hdr, short len) {
    uint32_t sum = 0;
    for(; len >= 2; len -= 2)
      sum += *(hdr++);
    if (len == 1)
      sum += *((unsigned char*)hdr);

    sum = (sum >> 16) + (sum & 0xFFFF);

    return ~sum;
}

/**
 * Send an dns-answer-packet to the helper
 */
static void
helper_write(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx) {
    if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
      return;

    struct answer_packet_list* ans = answer_proc_head;
    size_t len = ntohs(ans->pkt.hdr.size);

    GNUNET_assert(ans->pkt.subtype == GNUNET_DNS_ANSWER_TYPE_IP);

    size_t data_len = len - sizeof(struct answer_packet) + 1;
    size_t net_len = sizeof(struct ip_hdr) + sizeof(struct udp_dns) + data_len;
    size_t pkt_len = sizeof(struct GNUNET_MessageHeader) + sizeof(struct pkt_tun) + net_len;

    struct ip_udp_dns* pkt = alloca(pkt_len);
    memset(pkt, 0, pkt_len);

    /* set the gnunet-header */
    pkt->shdr.size = htons(pkt_len);
    pkt->shdr.type = htons(GNUNET_MESSAGE_TYPE_VPN_HELPER);

    /* set the tun-header (no flags and ethertype of IPv4) */
    pkt->tun.flags = 0;
    pkt->tun.type = htons(0x0800);

    /* set the ip-header */
    pkt->ip_hdr.version = 4;
    pkt->ip_hdr.hdr_lngth = 5;
    pkt->ip_hdr.diff_serv = 0;
    pkt->ip_hdr.tot_lngth = htons(net_len);
    pkt->ip_hdr.ident = 0;
    pkt->ip_hdr.flags = 0;
    pkt->ip_hdr.frag_off = 0;
    pkt->ip_hdr.ttl = 255;
    pkt->ip_hdr.proto = 0x11; /* UDP */
    pkt->ip_hdr.chks = 0; /* Will be calculated later*/
    pkt->ip_hdr.sadr = ans->pkt.from;
    pkt->ip_hdr.dadr = ans->pkt.to;

    pkt->ip_hdr.chks = calculate_ip_checksum((uint16_t*)&pkt->ip_hdr, 5*4);

    /* set the udp-header */
    pkt->udp_dns.udp_hdr.spt = htons(53);
    pkt->udp_dns.udp_hdr.dpt = ans->pkt.dst_port;
    pkt->udp_dns.udp_hdr.len = htons(net_len - sizeof(struct ip_hdr));
    pkt->udp_dns.udp_hdr.crc = 0; /* Optional for IPv4 */

    memcpy(&pkt->udp_dns.data, ans->pkt.data, data_len);

    GNUNET_CONTAINER_DLL_remove (answer_proc_head, answer_proc_tail, ans);
    GNUNET_free(ans);

    /* FIXME */ GNUNET_DISK_file_write(fh_to_helper, pkt, pkt_len);

    /* if more packets are available, reschedule */
    if (answer_proc_head != NULL)
      GNUNET_SCHEDULER_add_write_file (sched,
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       fh_to_helper,
				       &helper_write,
				       NULL);
}

/**
 * Receive packets from the helper-process
 */
static void
message_token(void *cls,
	      void *client,
	      const struct GNUNET_MessageHeader *message) {
    GNUNET_assert(ntohs(message->type) == GNUNET_MESSAGE_TYPE_VPN_HELPER);

    struct tun_pkt *pkt_tun = (struct tun_pkt*) message;

    /* ethertype is ipv6 */
    if (ntohs(pkt_tun->tun.type) == 0x86dd)
      {
	struct ip6_pkt *pkt6 = (struct ip6_pkt*) message;
	struct ip6_tcp *pkt6_tcp;
	struct ip6_udp *pkt6_udp;

	pkt_printf(pkt6);
	switch(pkt6->ip6_hdr.nxthdr)
	  {
	  case 0x06:
	    pkt6_tcp = (struct ip6_tcp*)pkt6;
	    pkt_printf_ip6tcp(pkt6_tcp);
	    break;
	  case 0x11:
	    pkt6_udp = (struct ip6_udp*)pkt6;
	    pkt_printf_ip6udp(pkt6_udp);
	    if (ntohs(pkt6_udp->udp_hdr.dpt) == 53) {
		pkt_printf_ip6dns((struct ip6_udp_dns*)pkt6_udp);
	    }
	    break;
	  }
      }
    /* ethertype is ipv4 */
    else if (ntohs(pkt_tun->tun.type) == 0x0800)
      {
	struct ip_pkt *pkt = (struct ip_pkt*) message;
	struct ip_udp *udp = (struct ip_udp*) message;
	GNUNET_assert(pkt->ip_hdr.version == 4);

	/* Send dns-packets to the service-dns */
	if (pkt->ip_hdr.proto == 0x11 && ntohs(udp->udp_hdr.dpt) == 53 )
	  {
	    /* 9 = 8 for the udp-header + 1 for the unsigned char data[1]; */
	    size_t len = sizeof(struct query_packet) + ntohs(udp->udp_hdr.len) - 9;

	    struct query_packet_list* query = GNUNET_malloc(len + 2*sizeof(struct query_packet_list*));
	    query->pkt.hdr.type = htons(GNUNET_MESSAGE_TYPE_LOCAL_QUERY_DNS);
	    query->pkt.hdr.size = htons(len);
	    query->pkt.orig_to = pkt->ip_hdr.dadr;
	    query->pkt.orig_from = pkt->ip_hdr.sadr;
	    query->pkt.src_port = udp->udp_hdr.spt;
	    memcpy(query->pkt.data, udp->data, ntohs(udp->udp_hdr.len) - 8);

	    GNUNET_CONTAINER_DLL_insert_after(head, tail, tail, query);

	    if (dns_connection != NULL)
	      GNUNET_CLIENT_notify_transmit_ready(dns_connection,
						  len,
						  GNUNET_TIME_UNIT_FOREVER_REL,
						  GNUNET_YES,
						  &send_query,
						  NULL);
	  }
      }
}

/**
 * Connect to the service-dns
 */
static void
connect_to_service_dns (void *cls,
			const struct GNUNET_SCHEDULER_TaskContext *tc) {
    if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      return;
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connecting to service-dns\n");
    GNUNET_assert (dns_connection == NULL);
    dns_connection = GNUNET_CLIENT_connect (sched, "dns", cfg);
    GNUNET_CLIENT_receive(dns_connection, &dns_answer_handler, NULL, GNUNET_TIME_UNIT_FOREVER_REL);

    /* If a packet is already in the list, schedule to send it */
    if (head != NULL)
      GNUNET_CLIENT_notify_transmit_ready(dns_connection,
					  ntohs(head->pkt.hdr.size),
					  GNUNET_TIME_UNIT_FOREVER_REL,
					  GNUNET_YES,
					  &send_query,
					  NULL);
}

/**
 * This gets scheduled with cls pointing to an answer_packet and does everything
 * needed in order to send it to the helper.
 *
 * At the moment this means "inventing" and IPv6-Address for .gnunet-services and
 * doing nothing for "real" services.
 */
static void
process_answer(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tc) {
    struct answer_packet* pkt = cls;

    /* This answer is about a .gnunet-service
     *
     * It contains an almost complete DNS-Response, we have to fill in the ip
     * at the offset pkt->addroffset
     */
    if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_SERVICE)
      {
	unsigned char ip6addr[16];

	pkt->subtype = GNUNET_DNS_ANSWER_TYPE_IP;
	memcpy(ip6addr, (int[]){htons(0x1234)}, 2);
	memcpy(ip6addr+2, &pkt->peer, 7);
	memcpy(ip6addr+9, &pkt->service_descriptor, 7);

	memcpy(((char*)pkt)+ntohs(pkt->addroffset), ip6addr, 16);

	  /*FIXME:
	   * -save DNS_Record into hashmap, pointed to by ip
	   * -regularily walk through hashmap, deleting old entries
	   *  when is an entry old?
	   *  have a last-used field
	   *  don't remove if last-used "recent", ask dht again if record expired
	   */
      }

    struct answer_packet_list* list = GNUNET_malloc(htons(pkt->hdr.size) + 2*sizeof(struct answer_packet_list*));

    memcpy(&list->pkt, pkt, htons(pkt->hdr.size));

    GNUNET_CONTAINER_DLL_insert_after(answer_proc_head, answer_proc_tail, answer_proc_tail, list);

    GNUNET_SCHEDULER_add_write_file (sched, GNUNET_TIME_UNIT_FOREVER_REL, fh_to_helper, &helper_write, NULL);

    return;
}

/**
 * This receives packets from the service-dns and schedules process_answer to
 * handle it
 */
static void
dns_answer_handler(void* cls, const struct GNUNET_MessageHeader *msg) {
    /* the service disconnected, reconnect after short wait */
    if (msg == NULL)
      {
	GNUNET_CLIENT_disconnect(dns_connection, GNUNET_NO);
	dns_connection = NULL;
	GNUNET_SCHEDULER_add_delayed (sched,
				      GNUNET_TIME_UNIT_SECONDS,
				      &connect_to_service_dns,
				      NULL);
	return;
      }

    /* the service did something strange, reconnect immediately */
    if (msg->type != htons(GNUNET_MESSAGE_TYPE_LOCAL_RESPONSE_DNS))
      {
	GNUNET_break (0);
	GNUNET_CLIENT_disconnect(dns_connection, GNUNET_NO);
	dns_connection = NULL;
	GNUNET_SCHEDULER_add_now (sched,
				  &connect_to_service_dns,
				  NULL);
	return;
      }
    void *pkt = GNUNET_malloc(ntohs(msg->size));

    memcpy(pkt, msg, ntohs(msg->size));

    GNUNET_SCHEDULER_add_now(sched, process_answer, pkt);
    GNUNET_CLIENT_receive(dns_connection, &dns_answer_handler, NULL, GNUNET_TIME_UNIT_FOREVER_REL);
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param sched the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched_,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg_) {
    sched = sched_;
    mst = GNUNET_SERVER_mst_create(&message_token, NULL);
    cfg = cfg_;
    restart_hijack = 0;
    GNUNET_SCHEDULER_add_now (sched, connect_to_service_dns, NULL);
    GNUNET_SCHEDULER_add_now (sched, start_helper_and_schedule, NULL);
    GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls); 
}

/**
 * The main function to obtain template from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv) {
    static const struct GNUNET_GETOPT_CommandLineOption options[] = {
	GNUNET_GETOPT_OPTION_END
    };

    return (GNUNET_OK ==
	    GNUNET_PROGRAM_run (argc,
				argv,
				"gnunet-daemon-vpn",
				gettext_noop ("help text"),
				options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-daemon-vpn.c */
