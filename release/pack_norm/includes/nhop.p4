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

action nhop_client_set( ) {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, 0);
}

table nhop_client_tab {
    actions {
        nhop_client_set;
    }
    default_action  : nhop_client_set;
    size : 1;
}

action nhop_server_set( ) {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, 48);
}

table nhop_server_tab {
    actions {
        nhop_server_set;
    }
    default_action  : nhop_server_set;
    size : 1;
}

action drop_and_exit () {
    drop();
    exit();
}

table drop_and_exit_tab {
    actions {
        drop_and_exit;
    }

    default_action: drop_and_exit;
    size : 1;
}

#endif