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
#include "./includes/ipd.p4"
#include "./includes/cmin_1st_all_mal.p4"
#include "./includes/rtt.p4"
#include "./includes/nhop.p4"
#include "./includes/conn.p4"




/*===============================================================================================*/
/* the ingress */
control ingress {

    apply (split_tstamp_high32_tab); //obtain timestamp for this packet
    apply (split_seq_low16_tab);
    apply (split_ack_low16_tab);
    apply (convert_dataoffset_to_32_tab); // convert dataoffset to 32 bits
    apply (convert_totallen_to_32_tab); // convert totallen to 32 bits

    apply (conn_tab) {

        /* no such conn exists, send to control plane */
        miss {
            apply (generate_entry_digest_tab);
        }

        /* existing conn, modify state variables */
        hit {
            // from server to client
            if (ig_intr_md.ingress_port == PORT_SERVER){

                apply (read_update_cmin_1st_ipd_count_tab); //get the number of ipds we have stored for this connection

                apply (read_update_ts_tab); //update the timestamp for this connection

                apply (compute_ipd_tab); // compute the ipd
                apply (read_update_cmin_1st_thresh_tab);

                apply (read_update_cmin_1st_right_hash1_tab);

                apply (read_update_cmin_1st_right_hash2_tab);

                apply (read_update_cmin_1st_right_hash3_tab);

                apply (comp_cmin_1st_step1_tab);
                apply (comp_cmin_1st_step2_tab);

                apply (check_cmin_1st_tab);

                apply (read_update_timing_mal_bit_tab);

                if(meta.timing_mal_bit == 1){
                    apply (generate_ipd_digest_tab); // send ipd to control plane
                }
            } else {
                apply (shift_dataoffset_tab); // dataoffset << 2
                apply (add_totallen_seq_tab); // highwater = totallen + tcp.seq

                // from client to the server, ack packets
                if (ig_intr_md.ingress_port == PORT_CLIENT){
                    apply (read_rtt_tstamp_tab);
                    // compuate rtt
                    apply (cal_rtt_tab);
                    // split the rtt into 16 bits
                    apply (split_rtt_low16_tab);
                    // put the rtt into IPID
                    apply (put_rtt_tab);

                }
                // from CPU and it is data packet sent to the client, we update the highwater and tstamp
                else if (ig_intr_md.ingress_port == CPU_OUT) {
                    // setup a bit, if the data packet is sent to the client
                    apply (filter_cpu_data_pkt_tab);
                    apply (minus_dataoffset_tab); // highwater -= dataoffset

                    if (meta.data_cpu == 1){
                        apply (get_highwater_tab); // highwater -= 20

                        apply (split_highwater_low16_tab);
                        apply (update_rtt_tstamp_tab);
                    }
                }
            }
        }
    }

    apply (nhop_cp_tab){ // send packets to cpu if cannot pass KS-Test on control plane
        hit{
            // packets from client side or from server side
            if (ig_intr_md.ingress_port == 0 or ig_intr_md.ingress_port == 48){
                apply (nhop_cpu_tab);
            }
            // packets from cache
            else {
                apply (nhop);
            }
        }
        miss{
            apply (nhop); //last of all, forward
        }
    }
}


/*===============================================================================================*/
/* the egress*/
control egress {

}
