/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "packet.h"
#include "helper.h"
#include "cache.h"
#include "conn.h"

// outer variables
extern int pre_ack_enabled;
extern int period;
extern int attack_start_from;
extern int defense_thres;

// internal variables
static conn_t *conns;
static int num_conns_max;
static int num_seen_conns;
static struct in_addr server_ip;

static int parse_pkt_internal(const uint8_t *, ethernet_hdr_t **,
                              ip_hdr_t **, tcp_hdr_t **,
                              uint32_t *, uint32_t *,
                              uint32_t *, uint32_t *);
static void update_highwater(conn_t *c, parsed_pkt_t *p);
static int send_pre_ack_for_conn(conn_t *conn, pcap_t *handle_out);
extern long get_tstamp();

extern double period_with_jitter;
double rtt_measured;

void check_cache_stuck(pcap_t *handle_out)
{
   int k;

   for (k = 0; k < num_seen_conns; k ++) {
      conn_t *conn = &conns[k];
      assert(conn->status == CONN_STARTED || conn->status == CONN_STOPPED);
      cache_info_t *info = &conn->cache_info;

      if (info->num_cached == 0 || conn->status == CONN_STOPPED ||
          is_cache_stopped(info)) {
         // do nothing
      } else if (info->burst_start_old == info->burst_start) {
         clean_cache(info, handle_out);
         INFO("conn[%d]: cache watchdog time out, cleaning cache",
              conn->id);
      }

      info->burst_start_old = info->burst_start;
   }
}

void print_stats_all_conns()
{
   int i;
   int num_used_cache = 0;

   for (i = 0; i < num_seen_conns; i ++) {
      conn_t *conn = &conns[i];
      num_used_cache += conn->cache_info.num_not_acked;
   }

   INFO("%d conns use %d entries (%.1f per conn), consumes %f MB memory",
        num_seen_conns, num_used_cache, ((double)num_used_cache)/num_seen_conns,
        ((double) num_used_cache) * 1514 / 1000000);
}

// checksum and pre ack

// calculating checksum.
// https://github.com/snabbco/snabb/blob/master/src/lib/checksum.c
static uint16_t cksum_generic(unsigned char *p, size_t len, uint16_t initial)
{
  uint32_t sum = htons(initial);
  const uint16_t *u16 = (const uint16_t *)p;

  while (len >= (sizeof(*u16) * 4)) {
    sum += u16[0];
    sum += u16[1];
    sum += u16[2];
    sum += u16[3];
    len -= sizeof(*u16) * 4;
    u16 += 4;
  }
  while (len >= sizeof(*u16)) {
    sum += *u16;
    len -= sizeof(*u16);
    u16 += 1;
  }

  /* if length is in odd bytes */
  if (len == 1)
    sum += *((const uint8_t *)u16);

  while(sum>>16)
    sum = (sum & 0xFFFF) + (sum>>16);
  return ~((uint16_t)sum);
}

// modified from cksum_generic, compute cksum for p1 and p2 and return the sum
// this is useful because the pesudo header and tcp part are not in
// continuous memory
static uint16_t cksum_generic2(uint8_t *p1, size_t len1,
                               uint8_t *p2, size_t len2)
{
  assert(len1 % 2 == 0);
  assert(len2 % 2 == 0);

  uint32_t sum1 = 0;
  uint32_t sum2 = 0;
  uint32_t sum3 = 0;
  const uint16_t *u16_1 = (const uint16_t *)p1;
  const uint16_t *u16_2 = (const uint16_t *)p2;

  while (len1 >= (sizeof(*u16_1) * 4)) {
    sum1 += u16_1[0];
    sum1 += u16_1[1];
    sum1 += u16_1[2];
    sum1 += u16_1[3];
    len1 -= sizeof(*u16_1) * 4;
    u16_1 += 4;
  }

  while (len1 >= sizeof(*u16_1)) {
    sum1 += *u16_1;
    len1 -= sizeof(*u16_1);
    u16_1 += 1;
  }

  while (len2 >= (sizeof(*u16_2) * 4)) {
    sum2 += u16_2[0];
    sum2 += u16_2[1];
    sum2 += u16_2[2];
    sum2 += u16_2[3];
    len2 -= sizeof(*u16_2) * 4;
    u16_2 += 4;
  }

  while (len2 >= sizeof(*u16_2)) {
    sum2 += *u16_2;
    len2 -= sizeof(*u16_2);
    u16_2 += 1;
  }

  sum3 = sum1 + sum2;
  while(sum3>>16)
    sum3 = (sum3 & 0xFFFF) + (sum3>>16);
  return ~((uint16_t)sum3);
}

static void prepare_pre_ack(conn_t *conn, parsed_pkt_t *p)
{
   assert(pre_ack_enabled);
   assert(p->l3->ip_src.s_addr == server_ip.s_addr);

   uint8_t *pre_ack = conn->pre_ack;
   uint32_t pre_ack_len = SIZE_ETHERNET_HDR + p->ip_hdr_len + p->tcp_hdr_len;
   conn->pre_ack_len = pre_ack_len;

   // compose the pre-ack packet
   memcpy((void *)(pre_ack), (void *)(p->l2), pre_ack_len);

   // get the pointers to l3 and l4 headers
   parsed_pkt_t *p2 = &conn->parsed_pre_ack;
   parse_pkt(pre_ack, p2);

   LOG(0, "conn[%d]: composing pre-ack, iplen=%d, tcplen=%d, total_len=%d",
       conn->id, p2->ip_hdr_len, p2->tcp_hdr_len, pre_ack_len);

   // swap MAC address
   memcpy((void *)(p2->l2->ether_dhost),
          (void *)(p->l2->ether_shost), ETHER_ADDR_LEN);
   memcpy((void *)(p2->l2->ether_shost),
          (void *)(p->l2->ether_dhost), ETHER_ADDR_LEN);

   // swap IP addr
   p2->l3->ip_src.s_addr = p->l3->ip_dst.s_addr;
   p2->l3->ip_dst.s_addr = p->l3->ip_src.s_addr;

   // swap TCP port
   p2->l4->th_sport = p->l4->th_dport;
   p2->l4->th_dport = p->l4->th_sport;

   // pre ack has no data.
   p2->l3->ip_len = htons(p->ip_hdr_len + p->tcp_hdr_len);

   // update TCP flags
   p2->l4->th_flags = TH_ACK;
   p2->l4->th_win = htons(conn->pre_ack_win);
}


static int parse_pkt_internal(const uint8_t *pkt,
                              ethernet_hdr_t **l2,
                              ip_hdr_t       **l3,
                              tcp_hdr_t      **l4,
                              uint32_t *ip_hdr_len,
                              uint32_t *tcp_hdr_len,
                              uint32_t *total_len,
                              uint32_t *payload_len)
{
	*l2 = (struct ethernet_hdr_t*) pkt;
	*l3 = (struct ip_hdr_t*) (pkt + SIZE_ETHERNET_HDR);

	uint32_t size_ip = IP_HL(*l3) * 4;
	if (size_ip < 20) {
		// ERR("invalid IP header length: %u, not IP packet", size_ip);
      return -1;
	}

   *l4 = (struct tcp_hdr_t *) (pkt + SIZE_ETHERNET_HDR + size_ip);
	uint32_t size_tcp = TH_OFF(*l4) * 4;
	if (size_tcp < 20) {
		// ERR("invalid TCP header length: %u, not TCP packet", size_tcp);
      return -1;
	}

   *ip_hdr_len  = size_ip;
   *tcp_hdr_len = size_tcp;
   *total_len   = SIZE_ETHERNET_HDR + ntohs((*l3)->ip_len);
   *payload_len = ntohs((*l3)->ip_len) - size_ip - size_tcp;

   return 0;
}

// helper function
int parse_pkt(const uint8_t *pkt, parsed_pkt_t *res)
{
   assert(res);
   assert(pkt);
   return parse_pkt_internal(pkt, &res->l2, &res->l3, &res->l4,
                             &res->ip_hdr_len, &res->tcp_hdr_len,
                             &res->total_len, &res->payload_len);
}

static int send_pre_ack_for_conn(conn_t *conn, pcap_t *handle_out)
{
   int ret;

   // we haven't received any packet or number of packets is too small
   if (conn->pre_ack_empty || conn->num_data_total < conn->pre_ack_thres) {
      return 0;
   }
   assert(conn->highwater);

   // scan the cache entries and determine the highwater we should pre ack
   cache_info_t *info = &conn->cache_info;
   int move_count = 0;
   cache_entry_t *e;

   for (int k = info->pos_last_pre_ack_vagas; k < info->pos_last_pre_ack_vagas + info->num_not_pre_acked_vegas; k ++) {
      int idx = k % (info->size);
      e = &info->cache[idx];
      long current_tstamp = get_tstamp();
      long entry_tstamp = e->tstamp;

      if (current_tstamp - entry_tstamp < period_with_jitter || move_count >= 20){
         break;
      }

      move_count += 1;
   }

   if (move_count == 0){
      return 0;
   }

   // the first unacked packet that hasn't reached out the time period
   uint32_t seq = e->seq + e->payload_len;

   // we don't send duplicate ack
   if (seq == conn->last_pre_ack_vegas){
      return 0;
   }


   parsed_pkt_t *p = &conn->parsed_pre_ack;
   // Update IP checksum
   // clear IP checksum field before calculation
   p->l3->ip_sum = 0;
   p->l3->ip_sum = cksum_generic((uint8_t *)p->l3, p->ip_hdr_len, 0);

   // Update TCP checksum
   pseudo_tcp_header_t pseu_th = {
      .srcAddr = p->l3->ip_src.s_addr,
      .dstAddr = p->l3->ip_dst.s_addr,
      .zero = 0,
      .protocol = IPPROTO_TCP,
      .TCP_len  = htons(p->tcp_hdr_len),
   };

   // clear checksum field before calculation
   p->l4->th_ack = htonl(seq);
   p->l4->th_seq = conn->sender_ack;
   p->l4->th_sum = 0;
   p->l4->th_sum = cksum_generic2((uint8_t *) &pseu_th,
                                  sizeof(pseu_th),
                                  (uint8_t *) p->l4,
                                  p->tcp_hdr_len);

   LOG(0, "conn[%d]: sending one pre-ack packet, ack=%u, pre_ack_len=%d",
       conn->id, ntohl(p->l4->th_ack), conn->pre_ack_len);

   // send the pre ack packet back to the switch.
   ret = pcap_sendpacket(handle_out, (const uint8_t *) p->l2,
                         conn->pre_ack_len);
   if (ret == 0) {
      info->pos_last_pre_ack_vagas = (info->pos_last_pre_ack_vagas + move_count) % (info->size);
      info->num_not_pre_acked_vegas -= move_count;
      conn->last_pre_ack_vegas = seq;
      assert(info->num_not_pre_acked_vegas >= 0);
   } else {
      ERR("failed to send pre ack for conn[%d]", conn->id);
   }
   return ret;
}

int send_pre_ack(pcap_t *handle_out)
{
   assert(handle_out);
   assert(pre_ack_enabled);
   assert(period);
   int k, ret = 0;

   for (k = 0; k < num_seen_conns; k ++) {
      conn_t *conn = &conns[k];
      assert(conn->status == CONN_STARTED || conn->status == CONN_STOPPED);

      conn->budget_in_ms -= period;
      if (conn->budget_in_ms <= 0) {
         // recharge the budget
         conn->budget_in_ms = conn->rtt_in_ms;
         ret = send_pre_ack_for_conn(conn, handle_out);
         if (ret) {
            ERR("failed to send pre ack for conn[%d]", conn->id);
            ret = -1;
         }
      }
   }

   return ret;
}

static void update_highwater(conn_t *c, parsed_pkt_t *p)
{
   uint32_t seq = ntohl(p->l4->th_seq);
   c->highwater = seq + p->payload_len;
   LOG(0, "conn[%d]: highwater updated to %u", c->id, c->highwater);
}

int handle_data_pkt(conn_t *c, parsed_pkt_t *p, pcap_t *handle_out)
{
   assert(c->status == CONN_STARTED || c->status == CONN_STOPPED);

   int ret = 0;
   cache_info_t *info = &c->cache_info;

   c->num_data_total += 1;

   // data packets must from server side.
   assert(p->l3->ip_src.s_addr == server_ip.s_addr);

   // deliver this packet if cache is already stopped (e.g., FIN detected)
   if (is_cache_stopped(info)) {
      LOG(0, "conn[%d]: cache of stopped, sending one pkt directly", c->id);
      return pcap_sendpacket(handle_out, (const uint8_t *) p->l2,p->total_len);
   }

   if (pre_ack_enabled) {
      // handle out of order data packets
      uint32_t seq = ntohl(p->l4->th_seq);
      if (seq < c->highwater) {
         LOG(0, "conn[%d]: ignore ooo packet seq=%u, highwater=%u",
             c->id, seq, c->highwater);
         return 0;
      }

      update_highwater(c, p);
      // update sender's ack number, note: no need to convert byte sequence
      c->sender_ack = p->l4->th_ack;

      // craft a pre-ack template packet if not exist
      if (c->pre_ack_empty) {
         prepare_pre_ack(c, p);
         c->pre_ack_empty = 0;
      }
   }

   // stop caching once we detect a FIN packet.
   // XXX: should we stop sending the pre ack packets ?
   if (p->l4->th_flags & TH_FIN) {
      INFO("conn[%d]: got a FIN packet, seq %u", c->id,
           ntohl(p->l4->th_seq));

      // send out all cached packets
      ret = clean_cache(info, handle_out);
      if (ret) {
         ERR("conn[%d]: failed to clean up cache", c->id);
         return ret;
      }

      assert(info->num_cached == 0);
      info->status = CACHE_STOPPED;
      c->highwater += 1;
      return pcap_sendpacket(handle_out, (const uint8_t*) p->l2, p->total_len);
   }

/*
   if (c->last_real_ack >= p->l4->th_seq + p->payload_len) {
      LOG(0, "conn[%d]: this data seq=%u + plen=%d is behind real ack=%u from client, "
          "no need to cache this data pkt.",
          c->id, p->l4->th_seq, p->payload_len, c->last_real_ack);
      return pcap_sendpacket(handle_out, (const uint8_t*) p->l2, p->total_len);
   }
*/

   // we cannot over-write a pkt that's not ack'ed.
   if (is_cache_full(info)) {
      ERR("conn[%d]: cache is full, cant cache seq=%u, entry used by seq=%u",
          c->id, ntohl(p->l4->th_seq), next_entry_to_cache(info)->seq);
      return -1;
   }

   // detect buffer bloat attacks
   if (defense_thres &&
      info->num_not_acked * 1514 > c->pre_ack_win * defense_thres ) {
      INFO("conn[%d] buffer bloat attack detected (buffer size=%d, thres=%d)",
           c->id, info->num_not_acked * 1514, c->pre_ack_win * defense_thres);
      clean_cache(info, handle_out);
      info->status = CACHE_STOPPED;
      info->num_not_acked = 0;
      // TODO: clean up the cache
      return 0;
   }

   // cache this packet
   cache_pkt(info, p, c->num_data_cached);
   c->num_data_cached += 1;
   info->num_not_pre_acked_vegas += 1;
   long current_tstamp = get_tstamp();
   //printf("receive a data pkt %u, %ld\n", ntohl(p->l4->th_seq), current_tstamp);

   // check if we need to send all cached packets
   if (info->num_cached == c->burst_size) {
      ret = clean_cache(info, handle_out);
      if (ret) {
         ERR("conn[%d]: failed to clean up cache", c->id);
         return ret;
      }
      if (period == 0) {
         // TODO: how to send ACKs after cache is stopped?
         LOG(0, "conn[%d], sending preACK for this burst", c->id);
         send_pre_ack_for_conn(c, handle_out);
      }
   }

   return 0;
}

int handle_real_ack(conn_t *conn, parsed_pkt_t *p, pcap_t *handle_out)
{
   assert(conn->status == CONN_STARTED || conn->status == CONN_STOPPED);

   int k, idx, ret;
   uint32_t this_ack = ntohl(p->l4->th_ack);
   cache_info_t *info = &conn->cache_info;

   // real ack must go to server side.
   assert(p->l3->ip_dst.s_addr == server_ip.s_addr);

   LOG(0, "conn[%d]: real ack=%u received", conn->id, this_ack);

   // only_cache mode: we don't produce ack, but just deliver real acks
   // back to the server.
   if (!pre_ack_enabled) {
      LOG(0, "conn[%d]: in cache-only mode, transferring real ack=%u directly",
          conn->id, this_ack);
      return pcap_sendpacket(handle_out, (const uint8_t*) p->l2, p->total_len);
   }

   // we don't have to deal with real acks if cache is stopped
   if (is_cache_stopped(info)) {
      LOG(0, "conn[%d]: cache stopped, ignoring real ack=%u",
          conn->id, this_ack);
      return 0;
   }

   // stop caching once we detect a FIN packet.
   // XXX: should we stop sending the pre ack packets ?
   if (p->l4->th_flags & TH_FIN) {
      INFO("conn[%d]: got a FIN packet from client, seq %u", conn->id,
           ntohl(p->l4->th_seq));

      // send out all cached packets
      ret = clean_cache(info, handle_out);
      if (ret) {
         ERR("conn[%d]: failed to clean up cache", conn->id);
         return ret;
      }

      assert(info->num_cached == 0);
      info->status = CACHE_STOPPED;
      return pcap_sendpacket(handle_out, (const uint8_t*) p->l2, p->total_len);
   }

   // ignore this ACK if all packets in cache have been ack'ed
   if (info->num_not_acked == 0) {
      LOG(0, "conn[%d]: num_not_acked==0, ignoring real ack=%u",
          conn->id, this_ack);
      return 0;
   }

   static int attack_started = 0;
   // ignore real acks to simulate bufferbloat attacker
   if (attack_start_from && conn->num_data_cached >= attack_start_from) {
      if (attack_started == 0) {
         INFO("buffer bloat attack start from data packet %d",
              attack_start_from);
      }
      attack_started = 1;
      LOG(0, "conn[%d]: real ack %u ignored to simulate bufferbloat",
          conn->id, this_ack);
      return 0;
   }

   // extrace the RTT data inside IPID
   uint16_t ipid = ntohs(p->l3->ip_id);
   float rtt = ipid * 65.536 / 1000.0;
   rtt_measured = rtt;
   // printf("rtt_measured:%f\n", rtt_measured);
   // printf("The rtt in ipid is %f ms\n", rtt);

   // ack and clean up packets in the cache
   for (k = info->j; k < info->j + info->num_not_acked; k ++) {
      idx = k % info->size;
      cache_entry_t *e = &info->cache[idx];

      if (e->sent == 0) {
         break;
      }

      if (e->seq + e->payload_len <= this_ack) {
         LOG(0, "conn[%d]: acking cache[%d] seq=%u, payload_len=%d, "
             "num_not_acked=%d",
             conn->id, idx, e->seq, e->payload_len, info->num_not_acked);

         // this packet must have been sent out
         assert(e->status == ENTRY_USED);
         assert(e->sent);
         assert(e->data);

         info->num_not_acked -= 1;
         e->data   = NULL;
         e->status = ENTRY_EMPTY;
         info->j = (info->j + 1) % info->size;
      } else {
         break;
      }
   }

   // dealing with duplicate ACKs
   if (this_ack == conn->last_real_ack) {
      LOG(0, "conn[%d]: duplicate ack %u received", conn->id, this_ack);

      // rtx the lost pkt
      // TODO: We might receive multiple duplicate ACKs
      // do we have to rtx it many times?
      // TODO: Now we rtx it whenever we see dup ACKs, what should be
      // a good threshold, e.g., 3?

      int notfound = 1;

      for (k = info->j; k < info->j + info->num_not_acked; k ++) {
         idx = k % info->size;
         cache_entry_t *e = &info->cache[idx];

         if (e->seq == this_ack) {

            notfound = 0;
            //if (e->rtxed) {
            if (e->rtxed && e->rtxed_count > 2) {
               //printf("%u, found not rtx\n", e->seq);
               break;
            }

            assert(e->data);
            assert(e->total_len);
            assert(e->status == ENTRY_USED);
            LOG(0, "conn[%d]: found cache[%d] has seq=%u, tlen=%d, rtx it",
                conn->id, idx, e->seq, e->total_len);
            ret = pcap_sendpacket(handle_out, (const uint8_t *) e->data,
                                  e->total_len);

            if (ret != 0) {
               printf("%u Cannot rtx\n", e->seq);
               ERR("conn[%d]: failed to rtx seq=%u", conn->id, e->seq);
               return -1;
            }

            //printf("%u, found and rtxed\n", e->seq);

            e->sent = 1;
            e->rtxed = 1;
            e->rtxed_count += 1;
            break;
         }
      }

      if (notfound == 1){
         //printf("Not found!!!!\n");
      }
   }

   // Update the latest real ACK we have seens
   if (this_ack != conn->last_real_ack) {
      conn->last_real_ack = this_ack;
   }

   return 0;
}


conn_t *get_conn_from_pkt(parsed_pkt_t *p, int *from_server)
{
   int i;
   conn_t *c;
   uint32_t sport, dport;
   sport = ntohs(p->l4->th_sport);
   dport = ntohs(p->l4->th_dport);

   LOG(0, "got a packet, num_seen_conns=%d",
       num_seen_conns);
   LOG(0, "sip=%s, sport=%d", inet_ntoa(p->l3->ip_src), sport);
   LOG(0, "dip=%s, sport=%d", inet_ntoa(p->l3->ip_dst), dport);

   for (i = 0; i < num_seen_conns; i ++) {
      c = &conns[i];

      if (p->l3->ip_src.s_addr == c->src_ip.s_addr   &&
          p->l3->ip_dst.s_addr == c->dst_ip.s_addr   &&
          sport == c->src_port &&
          dport == c->dst_port) {
         // server -> client direction
         assert(p->l3->ip_src.s_addr == server_ip.s_addr);
         *from_server = 1;
         break;
      } else if (p->l3->ip_src.s_addr == c->dst_ip.s_addr   &&
                 p->l3->ip_dst.s_addr == c->src_ip.s_addr   &&
                 sport == c->dst_port &&
                 dport == c->src_port) {
         // client -> server direction
         assert(p->l3->ip_dst.s_addr == server_ip.s_addr);
         *from_server = 0;
         break;
      }
   }

   if (i < num_seen_conns) {
      LOG(0, "conn[%d]: status=%d, got a packet, from_server=%d",
          c->id, c->status, *from_server);
      return c;
   }

   // this packet is from a new connection,
   // we assume that a new connection never reuse tuples from old connections
   if (num_seen_conns == num_conns_max) {
      ERR("Too many connections, cannot handle %dth conn", num_seen_conns);
      return NULL;
   }

   *from_server = p->l3->ip_src.s_addr == server_ip.s_addr ? 1 : 0;

   if (p->l3->ip_dst.s_addr != server_ip.s_addr &&
       p->l3->ip_src.s_addr != server_ip.s_addr) {
      LOG(0, "detected a connection not going through our server");
      LOG(0, "sip=%s", inet_ntoa(p->l3->ip_src));
      LOG(0, "dip=%s", inet_ntoa(p->l3->ip_dst));
      return NULL;
   }

   c = &conns[num_seen_conns];
   c->src_ip   = (*from_server) ? p->l3->ip_src : p->l3->ip_dst;
   c->dst_ip   = (*from_server) ? p->l3->ip_dst : p->l3->ip_src;
   c->src_port = (*from_server) ? sport : dport;
   c->dst_port = (*from_server) ? dport : sport;

   // TODO: construct pre-ack template for this new connection
   c->id = num_seen_conns;
   c->status = CONN_STARTED;
   c->cache_info.status = CACHE_STARTED;
   num_seen_conns += 1;

   INFO("received first packet for new conn[%d]", c->id);
   INFO("sip=%s, sport=%d", inet_ntoa(p->l3->ip_src), c->src_port);
   INFO("dip=%s, dport=%d", inet_ntoa(p->l3->ip_dst), c->dst_port);

   return c;
}

int initialize_conns(int num, int cache_size, int burst_size,
                     int pre_ack_win, int rtt, struct in_addr sip)
{
   int i, j;
   assert(num);
   INFO("initializing %d conns, cache_size=%d, burst_size=%d, "
        "pre_ack_win=%d, rtt=%d, server ip=%s",
        num, cache_size, burst_size, pre_ack_win, rtt, inet_ntoa(sip));

   num_conns_max = num;
   conns = malloc(sizeof(conn_t) * num_conns_max);
   if (!conns) {
      ERR("failed to malloc %d conn_t", num);
      return -1;
   }
   memset((void *)conns, 0, sizeof(conn_t) * num_conns_max);

   for (i = 0; i < num_conns_max; i ++) {
      conn_t *c = &conns[i];
      c->rtt_in_ms     = rtt;
      c->budget_in_ms  = rtt;
      c->pre_ack_empty = 1;
      c->pre_ack_thres = 0;
      c->pre_ack_win   = pre_ack_win;
      c->burst_size    = burst_size;
      c->status        = CONN_INITIALIZED;

      // initialize cache for this conn
      cache_info_t *info = &c->cache_info;

      info->cache = malloc(sizeof(cache_entry_t) * cache_size);
      if (!info->cache) {
         // TODO: delete allocated stuff
         ERR("conn[%d]: failed to malloc cache", c->id);
         return -1;
      }
      memset((void *)info->cache, 0, sizeof(cache_entry_t) * cache_size);

      info->size = cache_size;
      info->conn = c;
      info->status = CACHE_INITIALIZED;
   }

   server_ip.s_addr = sip.s_addr;
   return 0;
}
