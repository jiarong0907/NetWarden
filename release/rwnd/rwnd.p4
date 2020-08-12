/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/


/*===============================================================================================*/
/* macros */
#ifdef __TARGET_TOFINO__
  #include <tofino/constants.p4>
  #include <tofino/intrinsic_metadata.p4>
  #include <tofino/primitives.p4>
  #include <tofino/stateful_alu_blackbox.p4>
#else
  #error This program is intended to compile for Tofino P4 architecture only
#endif

#include "./includes/const.p4"
#include "./includes/headers.p4"
#include "./includes/parser.p4"
#include "./includes/storage.p4"
#include "./includes/nhop.p4"
#include "./includes/conn.p4"


/*===============================================================================================*/
/* the ingress */
control ingress {

    if (ig_intr_md.ingress_port == PORT_CPU){
        apply (nhop);
    } else {
        apply (conn_tab) {
            /* no such conn exists, send to control plane */
            miss {
                apply(generate_entry_digest_tab);
            }

            /* existing conn, modify state variables */
            hit {

                // from server to client
                if (ig_intr_md.ingress_port == PORT_SERVER){

                    apply (read_update_rwnd_last_ack_tab);
                    if (meta.rwnd_last_ack == tcp.ackNo){ // duplicate ack
                        apply (read_update_rwnd_dupack_count_tab);
                    } else {
                        apply (read_clear_rwnd_dupack_count_tab);
                    }

                    apply (read_update_rwnd_rtx_count_tab);
                    apply (read_update_reroute_bit_tab); // whether should reroute the flow to CPU


                    apply (get_rwnd_low_high_tab);

                    apply (read_update_rwnd_pkt_count_tab);
                    apply (read_update_enlarge_bit_tab);


                    if (meta.rwnd_enlarge_bit == 0) {
                        apply (shrink_rwnd_tab);
                    } else {
                        apply (enlarge_rwnd_tab);
                    }

                    apply (set_checksum_tab);

                } else{
                    apply (read_reroute_bit_tab);
                }
            }
        }

        apply (nhop);


        // Enlarging receiving window size could cause packet loss. If NetWarden preceive multiple (5) retransmission packets,
        // it will forward the flow to the cache. But we fond that if the enlarging threshold is carefully tuned,
        // this will never be triggered. The cache can be implemented based on the timing channel cache, but it is our future work.

        // if (meta.rwnd_reroute_bit == 1){
        //     apply (nhop_cpu_tab);
        // } else {
        //     apply (nhop);
        // }

    }
}


/*===============================================================================================*/
/* the egress*/
control egress {
}