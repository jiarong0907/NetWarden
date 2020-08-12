/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/



#ifndef NHOP_P4
#define NHOP_P4

/*======================================================================*/
/*forwarding table, really simple*/

action nop() {
}

action nhop_set(port) {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, port);
}

table nhop {
    reads {
        ipv4.dstAddr: exact;
    }
    actions {
        nhop_set;
    }
    default_action: nop;
    size : FORWARDING_TABLE_SIZE;
}

action nhop_cpu_set( ) {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, CPU_IN);
}

table nhop_cpu_tab {
    actions {
        nhop_cpu_set;
    }
    default_action  : nhop_cpu_set;
    size : 1;
}


/*===============================================================================================*/
/* control plane install entries for this table, forwarding packets to CPU */

action send_to_cp() {
    //modify_field(ig_intr_md_for_tm.ucast_egress_port, 192);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, CPU_IN);
}

table nhop_cp_tab{
    reads{
        ipv4.srcAddr: exact;
        tcp.srcPort: exact;
        ipv4.dstAddr: exact;
        tcp.dstPort: exact;
    }
    actions {
        send_to_cp;
        nop;
    }
    default_action: nop;
    size: FORWARDING_TABLE_SIZE;
}

#endif
