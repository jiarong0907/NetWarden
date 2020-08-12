/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>

#include "cache.h"
#include "conn.h"
#include "helper.h"
#include "packet.h"
#include "mytimer.h"

extern int pre_ack_enabled;
extern int loss;

void cache_pkt(cache_info_t *info, parsed_pkt_t *p, int id)
{
   cache_entry_t *e = next_entry_to_cache(info);

   assert(e->status == ENTRY_EMPTY);
   assert(info->num_cached    < info->size);
   assert(info->num_not_acked < info->size);
   assert(!is_cache_full(info));

   e->pkt_id      = id;
   e->data        = (const uint8_t *) p->l2;
   e->total_len   = p->total_len;
   e->payload_len = p->payload_len;
   e->seq         = ntohl(p->l4->th_seq);
   e->status      = ENTRY_USED;
   e->sent        = 0;

   info->num_cached    += 1;
   info->num_not_acked += 1;

   LOG(0, "conn[%d]: cached pkt %d at %d, seq=%u, len=%d, payload_len=%d,"
       " num_cached=%d, num_not_acked=%d", info->conn->id, e->pkt_id,
       info->i, e->seq, e->total_len, e->payload_len, info->num_cached,
       info->num_not_acked);

   info->i = (info->i + 1) % info->size;
}

int clean_cache(cache_info_t *info, pcap_t *handler)
{
   // cache must be running
   assert(is_cache_started(info));

   int ret, k, idx, burst_end;
   cache_entry_t *e;

   if (info->num_cached == 0) {
      LOG(0, "cache is empty, skip cleaning cache\n");
      return 0;
   }

   LOG(0, "conn[%d]: sending out all %d cached packets from %d",
       info->conn->id, info->num_cached, info->burst_start);
   burst_end = (info->burst_start + info->num_cached);
   assert(burst_end % info->size == info->i);

   for (k = info->burst_start; k < burst_end; k ++) {
      idx = k % (info->size);
      e = &info->cache[idx];

      if (e->data == NULL) {
         ERR("conn[%d]: cache[%d] data is null", info->conn->id, idx);
         return -1;
      }

      // normalize IPD of cached packets
      if (NORMALIZE_IPD_US) {
         usleep(NORMALIZE_IPD_US);
      }

      // hard-coded: drop a certain packet
      if (loss > 0 &&
          e->pkt_id > 0 &&
          e->pkt_id % loss == 0) {
         LOG(0, "conn[%d]: dropping cache[%d], id=%d, seq=%u, tlen=%d",
             info->conn->id, idx, e->pkt_id, e->seq, e->total_len);
      } else {
         assert(e->data);
         ret = pcap_sendpacket(handler, e->data, e->total_len);
         if (ret) {
            pcap_perror(handler, "send error\n");
            ERR("failed to send pkt_id=%d in cache[%d]", e->pkt_id, idx);
            return -1;
         }
      }

      e->sent = 1;
      info->num_cached -= 1;
      LOG(0, "conn[%d]: sent out cache[%d], seq=%u, total_len=%d",
          info->conn->id, idx, e->seq, e->total_len);

      // in cache-only mode, we don't have to handle packet loss
      if (!pre_ack_enabled) {
         e->data = NULL;
         e->status = ENTRY_EMPTY;
         info->num_not_acked -= 1;
      }
   }

   LOG(0, "conn[%d]: sent out all cached packets", info->conn->id);
   assert(info->num_cached == 0);
   info->burst_start = info->i;
   return 0;
}
