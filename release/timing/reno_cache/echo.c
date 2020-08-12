/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/

#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "mytimer.h"
#include "helper.h"
#include "cache.h"
#include "conn.h"
#include "packet.h"

int pre_ack_enabled;
int period;
int attack_start_from;
int defense_thres;
int loss = -1;
extern void print_stats_all_conns();
extern void check_cache_stuck(pcap_t *handle_out);

static void timer_handler(size_t timer_id, void *user_data)
{
   assert(pre_ack_enabled);
   assert(period);
   int ret;
   ret = send_pre_ack((pcap_t *) user_data);
   assert(ret == 0);
}

static void stats_handler(size_t timer_id, void *user_data)
{
   print_stats_all_conns();
}

static void wd_handler(size_t timer_id, void *user_data)
{
   check_cache_stuck((pcap_t *)user_data);
}

static void packet_handler(u_char *param,
                           const struct pcap_pkthdr *header,
                           const uint8_t *pkt)
{
   int k, ret, from_server;
   parsed_pkt_t parsed_res;

   pcap_t *handle_out = (pcap_t *)param;
   assert(handle_out);

   // parse this packet first
   ret = parse_pkt(pkt, &parsed_res);
   if (ret) {
      // ERR("failed to parse this pkt");
      return;
   }

   // which conn that this pkt belongs to?
   conn_t *conn = get_conn_from_pkt(&parsed_res, &from_server);
   if (!conn) {
      // ERR("failed to get conn from pkt");
      return;
      exit(-1);
      assert(0);
   }

   // detect if this is a real ack from the client side.
   if (from_server) {
      ret = handle_data_pkt(conn, &parsed_res, handle_out);
   } else {
      ret = handle_real_ack(conn, &parsed_res, handle_out);
   }

   if (ret) {
      ERR("failed to handle this %s packet", from_server ? "data":"real ack");
      exit(-1);
      assert(0);
   }

   return;
}


int main(int argc, char **argv)
{
   int c;
   size_t timer, stats_timer, wd_timer;
   static pcap_t *handle_in, *handle_out;
   char *device_in  = DEFAULT_DEVICE_IN;
   char *device_out = DEFAULT_DEVICE_OUT;
   char *filter_exp = DEFAULT_FILTER;
   int num = MAX_CONN_NUM;
   int cache_size = DEFAULT_CACHE_SIZE;
   int burst_size = DEFAULT_BURST_SIZE;
   int pre_ack_win = PRE_ACK_WIN;
   int rtt = DEFAULT_RTT_MS;
   period  = DEFAULT_TIMER_PERIOD_MS;
   pre_ack_enabled = 1;
   int stats_period = 0;
   int wd_period = 0;

   char *help = "========== cmd arguments =========\n"
                "-n: naive defense              (no option)\n"
                "-a: the no. of pkt to start attack, 0 to disable (int)\n"
                "-d: bufferbloat defense thres  (int)\n"
                "-s: stats period per sec       (int)\n"
                "-i: device_in                  (string)\n"
                "-o: device_out                 (string)\n"
                "-f: filter                     (string)\n"
                "-b: burse size                 (int)\n"
                "-p: timer period in ms         (int)\n"
                "-r: rtt in ms                  (int).\n"
                "-w: cache watch dog in ms      (int).\n"
                "-c: num. of conn               (int).\n"
                "-z: cache size                 (int).\n"
                "-l: loss rate(%%)              (float).\n"
                "-h: print this message.\n";

   while ((c = getopt(argc, argv, "a:d:c:hs:ni:o:f:b:p:r:w:z:l:")) != -1) {
      switch (c) {
         case 'a':
            attack_start_from = atoi(optarg);
            break;
         case 'z':
            cache_size = atoi(optarg);
            break;
         case 'd':
            defense_thres = atoi(optarg);
            break;
         case 'h':
            printf("%s", help);
            exit(0);
         case 'n':
            pre_ack_enabled = 0;
            break;
         case 's':
            stats_period = atoi(optarg);
            break;
         case 'w':
            wd_period = atoi(optarg);
            break;
         case 'i':
            device_in = optarg;
            break;
         case 'o':
            device_out = optarg;
            break;
         case 'f':
            filter_exp = optarg;
            break;
         case 'b':
            burst_size = atoi(optarg);
            break;
         case 'p':
            period = atoi(optarg);
            break;
         case 'r':
            rtt = atoi(optarg);
            break;
         case 'l':
            loss = 1 * 100 / atof(optarg);
            break;
         case 'c':
            num = atoi(optarg);
            break;
         case '?':
         default:
            ERR("unrecognized argument: %x", optopt);
            exit(-1);
      }
   }

   INFO("===== argument parsed =====\n"
        "preAck %s, in=%s, out=%s, filter=%s, burst_size=%d, period=%d, "
        "rtt=%d, loss=%d, attack start %d, defense %d",
        pre_ack_enabled ? "enabled":"disabled",
        device_in, device_out, filter_exp, burst_size, period, rtt, loss,
        attack_start_from, defense_thres);

   char error_buffer[PCAP_ERRBUF_SIZE];
   int snapshot_length = 65536;

   // End the loop after this many packets are captured, 0 means infinite
   int total_packet_count = 0;

   // open a handler for incoming packets
   handle_in = pcap_open_live(device_in, snapshot_length, 0, 0, error_buffer);
   if (handle_in == NULL) {
      ERR("failed to open handler %s", device_in);
      return -1;
   }
   INFO("in device %s opened", device_in);

   // if in and out device are same, we don't want to capture packets that we
   // send out.
   if (strcmp(device_in, device_out) == 0) {
      if (pcap_setdirection(handle_in, PCAP_D_IN) == -1) {
            ERR("failed to set direction for %s: %s",
                device_in, pcap_geterr(handle_in));
            return 2;
      }
      INFO("set capture direction of %s as IN", device_in);
   }

   // set capture filter to handle_in
   struct bpf_program fp;
   if (pcap_compile(handle_in, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN)
       == -1) {
		 ERR("failed compile filter %s: %s", filter_exp,
           pcap_geterr(handle_in));
		 return -1;
	}

	if (pcap_setfilter(handle_in, &fp) == -1) {
      ERR("failed to install filter %s: %s\n", filter_exp,
          pcap_geterr(handle_in));
      return -1;
   }

   INFO("filter %s applied to handle_in: %s", filter_exp, device_in);

   // open a handler for outcoming packets
   handle_out = pcap_open_live(device_out, snapshot_length,
                               0, 0, error_buffer);
   if (handle_in == NULL) {
      ERR("failed to open handler %s", device_out);
      return -1;
   }
   INFO("out device %s opened", device_out);

   // start a periodical timer
   // use this single timer to manage multiple conn
   initialize();
   if (pre_ack_enabled) {
      if (period) {
         timer = start_timer(period, timer_handler,
                             TIMER_PERIODIC, (void *)handle_out);
         INFO("preACK mode: period=%d", period);
      } else {
         INFO("preACK mode: ack every burst of packets");
      }
   }

   if (stats_period) {
      stats_timer = start_timer(stats_period * 1000, stats_handler,
                                TIMER_PERIODIC, NULL);
      INFO("stats timer started: period = %d s", stats_period);
   }

   if (wd_period) {
      wd_timer = start_timer(wd_period, wd_handler,
                             TIMER_PERIODIC, (void *)handle_out);
      INFO("watchdog timer started: period = %d ms", wd_period);
   }

   // initialize all conns and cache
   struct in_addr server_ip;
   int ret = inet_aton(SERVER_IP, &server_ip);
   assert(ret);

   ret = initialize_conns(num, cache_size, burst_size, pre_ack_win,
                          rtt, server_ip);
   if (ret) {
      ERR("failed to initialize %d connections", num);
      return -1;
   }

   INFO("all %d conns initialized", num);
   INFO("start capturing packets on %s interface", device_in);

   // start capturing every packet from in device
   pcap_loop(handle_in, total_packet_count,
             packet_handler,
             (uint8_t *)handle_out);

   return 0;
}
