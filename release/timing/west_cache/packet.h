/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

// pseudo header definition from
// https://github.com/rbaron/raw_tcp_socket/blob/master/raw_tcp_socket.c

typedef struct pseudo_tcp_header_t {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
} pseudo_tcp_header_t;


/*****************************************/
/*** header definitions from tcpdump.org**/
/*****************************************/

/* Ethernet header */
typedef struct ethernet_hdr_t {
#define MAC_ADDR_LEN 6
   /* Destination host address */
	uint8_t ether_dhost[MAC_ADDR_LEN];
   /* Source host address */
	uint8_t ether_shost[MAC_ADDR_LEN];
   /* IP? ARP? RARP? etc */
	uint16_t ether_type;
} ethernet_hdr_t;

#define SIZE_ETHERNET_HDR (sizeof(ethernet_hdr_t))

/* IP header */
typedef struct ip_hdr_t {
	uint8_t ip_vhl;		/* version << 4 | header length >> 2 */
	uint8_t ip_tos;		/* type of service */
	uint16_t ip_len;		/* total length */
	uint16_t ip_id;		/* identification */
	uint16_t ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	uint8_t  ip_ttl;		/* time to live */
	uint8_t  ip_p;		/* protocol */
	uint16_t ip_sum;		/* checksum */
	struct in_addr ip_src;
   struct in_addr ip_dst; /* source and dest address */
} ip_hdr_t;

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef uint32_t tcp_seq_t;

typedef struct tcp_hdr_t {
	uint16_t th_sport;	/* source port */
	uint16_t th_dport;	/* destination port */
	uint32_t th_seq;		/* sequence number */
	uint32_t th_ack;		/* acknowledgement number */
	uint8_t th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	uint16_t th_win;		/* window */
	uint16_t th_sum;		/* checksum */
	uint16_t th_urp;		/* urgent pointer */
} tcp_hdr_t;

typedef struct parsed_pkt_t {
   ethernet_hdr_t *l2;
   ip_hdr_t       *l3;
   tcp_hdr_t      *l4;
   uint32_t ip_hdr_len;
   uint32_t tcp_hdr_len;
   uint32_t total_len;
   uint32_t payload_len;
} parsed_pkt_t;

#endif /* PACKET_H */
