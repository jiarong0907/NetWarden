/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/


#ifndef NHOP_P4
#define NHOP_P4

/*===============================================================================================*/
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

#endif