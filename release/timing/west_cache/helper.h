/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/

#ifndef HELPER_H
#define HELPER_H

#include <stdio.h>

#define DEFAULT_LOG_LEVEL 1

// comment this macro when doing performance-aware testing
//#define DEBUG

#ifdef DEBUG
#define LOG(lvl, fmt, ...) {                                          \
   if (lvl <= DEFAULT_LOG_LEVEL) {                                 \
      printf("[LOG] %s:%s:%d: "fmt"\n",                           \
              __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);     \
   }                                                                 \
}
#else
   #define LOG(lvl, fmt, ...)
#endif

#define ERR(fmt, ...) {                                          \
   printf("[ERR] %s:%s:%d: "fmt"\n",                           \
           __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);     \
}

#define INFO(fmt, ...) {                                          \
   printf("[INFO] %s:%s:%d: "fmt"\n",                           \
           __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);     \
}


// In ds10
#define DEFAULT_DEVICE_IN    "ens3f0"
#define DEFAULT_DEVICE_OUT   "ens3f1"
#define DEFAULT_CACHE_SIZE   655360000
#define DEFAULT_BURST_SIZE   20
#define PRE_ACK_WIN          (29200*2)

//#define DEFAULT_FILTER "portrange 40000-40999"
#define DEFAULT_FILTER  ""

// which packet to drop, -1 disables drop
//#define PKT_TO_DROP (100)
#define PKT_TO_DROP (-1)

// If PERIOD is 0, it pre-acks every burst of packets
#define DEFAULT_TIMER_PERIOD_MS   1
#define DEFAULT_STATIC_PRE_ACK_PERIOD_MS   5
// default RTT of flows
#define DEFAULT_RTT_MS            1

#define NORMALIZE_IPD_US  0

// start pre-ack after receiving PRE_ACK_THRES packets
// #define PRE_ACK_THRES 0
// only cache packets size larger than CACHE_PKT_LEN_THRES
// #define CACHE_PKT_LEN_THRES 0

// hard-coded server port and IP to distinguish direction
#define SERVER_IP   ("192.168.0.1")

#define MAX_CONN_NUM 64

#endif /* HELPER_H */
