/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/

#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>
#include <pcap.h>
#include <assert.h>

struct parsed_pkt_t;
struct conn_t;

// an entry in the packet cache
typedef struct cache_entry_t {
   // i th packet being cached in this connection
   uint32_t pkt_id;

#define ENTRY_EMPTY   0  // empty entry, data should be NULL
#define ENTRY_USED    1  // used entry, data should not be NULL
   int status;

   int sent;
   int rtxed;
   int rtxed_count;

   const uint8_t *data;
   uint32_t seq;
   uint32_t total_len;
   uint32_t payload_len;

   long tstamp;   // the creating time of this entry
} cache_entry_t;

typedef struct cache_info_t {
#define CACHE_INVALID          0
#define CACHE_INITIALIZED      1
#define CACHE_STARTED          2
#define CACHE_STOPPED          3
   // cache status: e.g., started, stopped?
   int status;

   // size of the cache
   int size;

   // pointer to the pkt cache
   cache_entry_t *cache;

   // next pos to cache a pkt
   int i;
   // next pos to ack a pkt
   int j;

   // the start pos of this burst
   uint32_t burst_start;
   uint32_t burst_start_old;
   // number of packets in cache that are not sent out
   uint32_t num_cached;
   // number of packets in cache that are not acked
   uint32_t num_not_acked;

   // number of packets in cache that are not pre acked in the vegas mode
   uint32_t num_not_pre_acked_vegas;
   // the position of last pre ack in the vegas mode
   int pos_last_pre_ack_vagas;

   struct conn_t *conn;
} cache_info_t;

static inline int is_cache_stopped(cache_info_t *c)
{
   return (c->status == CACHE_STOPPED);
}

static inline int is_cache_started(cache_info_t *c)
{
   return (c->status == CACHE_STARTED);
}

static inline int is_cache_full(cache_info_t *c)
{
   if (c->cache[c->i].status == ENTRY_USED) {
      assert(c->num_not_acked == c->size);
      return 1;
   } else {
      return 0;
   }
}

static inline cache_entry_t *next_entry_to_cache(cache_info_t *c)
{
   return &c->cache[c->i];
}

static inline cache_entry_t *next_entry_to_ack(cache_info_t *c)
{
   return &c->cache[c->j];
}


// API definitions
extern void cache_pkt(cache_info_t *info, struct parsed_pkt_t *p, int id);
extern int  clean_cache(cache_info_t *info, pcap_t *handler);

#endif /* CACHE_H */
