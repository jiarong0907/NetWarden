/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/

#ifndef CONN_H
#define CONN_H

#include <stdint.h>
#include <pcap.h>
#include "packet.h"

#define ACK_PKT_SIZE 128

struct cache_info_t;

// per-flow information
typedef struct conn_t {
   // id th connection we have seen
   int id;

   // how many pkts we have cached in total
   uint64_t num_data_cached;
   // how many data packets received in total
   uint64_t num_data_total;
   // how many real acks we have received in total
   uint64_t num_real_acks;
   // how many duplicate acks we have received in total
   uint64_t num_dup_acks;
   // how many pre acks sent in total
   uint64_t num_pre_acks;

   // rtt is the period for sending pre ack
   uint32_t rtt_in_ms;

   // after how many ms we will send the next pre ack
   int budget_in_ms;

   // start pre ack after this number of packets;
   uint32_t pre_ack_thres;

   // only cache packets that are large than this threshold
   // uint32_t cache_pkt_len_min;

   uint32_t pre_ack_win;
   uint32_t burst_size;

#define CONN_INVALID           0
#define CONN_INITIALIZED       1
#define CONN_STARTED           2
#define CONN_STOPPED           3
   int status;
   struct cache_info_t cache_info;

   // buffer for the ACK packet template
   int pre_ack_empty;
   uint32_t pre_ack_len;
   uint8_t pre_ack[ACK_PKT_SIZE];
   parsed_pkt_t parsed_pre_ack;

   // = highest seq + payload_len = next ack no. expected to receive
   uint32_t highwater;
   // last pre-ack number we have sent, to avoid dupliate ack
   uint32_t last_pre_ack;
   // latest real ack we got the receiver
   uint32_t last_real_ack;

   // last pre-ack number we have sent in the vegas mode, to avoid dupliate ack
   uint32_t last_pre_ack_vegas;

   // connection tuples
   uint16_t src_port;
   uint16_t dst_port;
   struct in_addr src_ip;
   struct in_addr dst_ip;

   // latest ack number from sender
   // to compute the correct seq number of pre-ack
   uint32_t sender_ack;
} conn_t;


// TODO: define an array of conn_t instances? How about the size?


// API definitions
extern int parse_pkt(const uint8_t *pkt, parsed_pkt_t  *res);
extern int initialize_conns(int num, int cache_size, int burst_size,
                            int pre_ack_win, int rtt, struct in_addr sip);
extern conn_t *get_conn_from_pkt(parsed_pkt_t *p, int *from_server);
extern int handle_data_pkt(conn_t *conn, parsed_pkt_t *p, pcap_t *handle_out);
extern int handle_real_ack(conn_t *conn, parsed_pkt_t *p, pcap_t *handle_out);
extern int send_pre_ack();


#endif   /* CONN_H */
