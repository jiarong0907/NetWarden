/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/



#ifndef CONN_P4
#define CONN_P4

/*===============================================================================================*/
/*The digest table for sending to control plane*/

field_list digest_fields {
    meta.digest_type;

    tcp.srcPort;
    tcp.dstPort;
    ipv4.srcAddr;
    ipv4.dstAddr;

    meta.tstamp_ipd32;
}

action send_entry_digest() {
    modify_field(meta.digest_type, 1);
    generate_digest(0, digest_fields);
}

table generate_entry_digest_tab {
    actions {
      send_entry_digest;
    }
    default_action: send_entry_digest;
    size: 1;
}

/*===============================================================================================*/
/* generate digest to let CPU read registers */

action send_ipd_digest() {
    modify_field(meta.digest_type, 2);
    generate_digest(0, digest_fields);
}

table generate_ipd_digest_tab {
    actions {
      send_ipd_digest;
    }
    default_action: send_ipd_digest;
    size: 1;
}

/*===============================================================================================*/
/*The connection table*/

// Read value from register-indexed connection tables
action set_conn_idx(conn_idx) {
    modify_field(meta.conn_idx, conn_idx);
}

table conn_tab {
    reads {
        ipv4.srcAddr: exact;
        tcp.srcPort: exact;
        ipv4.dstAddr: exact;
        tcp.dstPort: exact;
    }
    actions {
        set_conn_idx;
        nop;
    }
    default_action: nop;
    size: MAX_CONN_TABLE_SIZE;
}


#endif