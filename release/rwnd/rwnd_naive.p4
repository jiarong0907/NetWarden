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

    apply (conn_tab) {
        /* no such conn exists, send to control plane */
        miss {
            apply(generate_entry_digest_tab);
        }

        /* existing conn, modify state variables */
        hit {
            // from server to client
            if (ig_intr_md.ingress_port == PORT_SERVER){
                apply (get_rwnd_shrinked_tab);
                apply (shrink_rwnd_tab);
                apply (set_checksum_tab);
            }
        }
    }

    apply (nhop);
}


/*===============================================================================================*/
/* the egress*/
control egress {

}