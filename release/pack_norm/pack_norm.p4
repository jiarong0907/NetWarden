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

    apply (get_syn_bit_left_tab);
    apply (split_tstamp_high32_tab); //obtain timestamp for this packet
    apply (convert_dataoffset_to_32_tab); // convert dataoffset to 32 bits
    apply (convert_totallen_to_32_tab); // convert totallen to 32 bits

    apply (get_syn_bit_right_tab);
    apply (shift_dataoffset_tab); // dataoffset << 2
    apply (add_totallen_seq_tab); // in_highwater = totallen + tcp.seq


    apply (conn_tab) {

        /* no such conn exists, send to control plane */
        miss {
            apply (generate_entry_digest_tab);
        }

        /* existing conn, modify state variables */
        hit {
            apply (minus_dataoffset_tab); // in_highwater -= dataoffset
            apply (read_update_last_ack_tab); // only update for PORT_SERVER

            if (ig_intr_md.ingress_port == PORT_SERVER){// from server to client

                apply (read_update_fin_state_tab);
                apply (cal_min_last_ack_tab);

                apply (read_in_highwater_tab);

                if (tcp.ackNo != meta.min_last_ack){
                    apply (read_update_repeat_ack_tab);

                    if (meta.repeat_ack == 0) { // skip the rtx

                        apply (check_pack_tab); // check whether it is a partial ack


                        apply (read_update_fack_tab); // read fack if a pack, otherwise update
                        apply (read_update_fack_ts_tab);

                        apply (compute_wait_time_tab);
                        apply (compute_min_wait_timeout_tab);

                        if(meta.flag_pack != 0){
                            if (meta.fin_state != 1 and meta.syn != 1){
                                if (meta.min_wait_timeout == TIMEOUT) {
                                    apply (generate_rewinded_fack_tab);
                                } else {
                                    apply (drop_and_exit_tab);
                                }
                            }
                        }
                    }
                } else {
                    apply (update_repeat_ack_tab);
                }
            }else if (ig_intr_md.ingress_port == PORT_CLIENT) {
                apply (update_in_highwater_tab); // read if ig_intr_md.ingress_port != PORT_IN, otherwise update
            }
        }
    }

    if (ig_intr_md.ingress_port == PORT_SERVER) { // ack packets come from server
        apply (nhop_client_tab); // forward to C
    } else if(ig_intr_md.ingress_port == PORT_CLIENT) { // data packets come from client
        apply (nhop_server_tab); // forward to server
    }
}


/*===============================================================================================*/
/* the egress*/
control egress {
}