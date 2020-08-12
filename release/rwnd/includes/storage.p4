/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/


#ifndef STORAGE_P4
#define STORAGE_P4

action get_rwnd_low_high (rwnd_lowerbound, rwnd_highbound) {
    modify_field(meta.window_shrinked, rwnd_lowerbound);
    modify_field(meta.window_enlarged, rwnd_highbound);
}

table get_rwnd_low_high_tab{
    reads {
        tcp.window : range;
    }

    actions {
        get_rwnd_low_high;
    }
    default_action  : get_rwnd_low_high;
    size : 1024;
}

action shrink_rwnd () {
    modify_field (tcp.window, meta.window_shrinked);
}

table shrink_rwnd_tab {
    actions {
        shrink_rwnd;
    }
    default_action  : shrink_rwnd;
    size : 1;
}

action enlarge_rwnd () {
    modify_field (tcp.window, meta.window_enlarged);
}

table enlarge_rwnd_tab {
    actions {
        enlarge_rwnd;
    }
    default_action  : enlarge_rwnd;
    size : 1;
}


/*===============================================================================================*/
/* to detect duplicate acks*/

register rwnd_last_ack {
  width: 32;
  instance_count: MAX_CONN_TABLE_SIZE;
}


blackbox stateful_alu read_update_rwnd_last_ack_alu {
    reg : rwnd_last_ack;

    update_lo_1_predicate: true;
    update_lo_1_value: tcp.ackNo;

    output_dst: meta.rwnd_last_ack;
    output_value: register_lo;
    output_predicate: true;
}

action read_update_rwnd_last_ack () {
    read_update_rwnd_last_ack_alu.execute_stateful_alu(meta.conn_idx);
}


table read_update_rwnd_last_ack_tab {
    actions {
        read_update_rwnd_last_ack;
    }

    default_action  : read_update_rwnd_last_ack;
    size : 1;
}


/*===============================================================================================*/
/* the number of duplicate acks for a connection, if the number larger than the threshold, send to control plane*/

register rwnd_dupack_count {
  width: 8;
  instance_count: MAX_CONN_TABLE_SIZE;
}


blackbox stateful_alu read_update_rwnd_dupack_count_alu {
    reg : rwnd_dupack_count;

    //update_lo_1_predicate: meta.rwnd_last_ack == tcp.ackNo;
    update_lo_1_predicate: true;
    update_lo_1_value: register_lo + 1;

    output_dst: meta.rwnd_dupack_count;
    output_value: alu_lo;
    output_predicate: true;
}

action read_update_rwnd_dupack_count () {
    read_update_rwnd_dupack_count_alu.execute_stateful_alu(meta.conn_idx);
}


table read_update_rwnd_dupack_count_tab {
    actions {
        read_update_rwnd_dupack_count;
    }

    default_action  : read_update_rwnd_dupack_count;
    size : 1;
}


blackbox stateful_alu read_clear_rwnd_dupack_count_alu {
    reg : rwnd_dupack_count;

    update_lo_1_predicate: true;
    update_lo_1_value: 0;

    output_dst: meta.rwnd_dupack_count;
    output_value: register_lo;
    output_predicate: true;
}

action read_clear_rwnd_dupack_count () {
    read_clear_rwnd_dupack_count_alu.execute_stateful_alu(meta.conn_idx);
}


table read_clear_rwnd_dupack_count_tab {
    actions {
        read_clear_rwnd_dupack_count;
    }

    default_action  : read_clear_rwnd_dupack_count;
    size : 1;
}

/*===============================================================================================*/
/* the number of rtx for a connection, if the number larger than the threshold, send to control plane*/

register rwnd_rtx_count {
  width: 8;
  instance_count: MAX_CONN_TABLE_SIZE;
}


blackbox stateful_alu read_update_rwnd_rtx_count_alu {
    reg : rwnd_rtx_count;

    condition_lo: meta.rwnd_dupack_count > 2;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: register_lo + 1;

    output_dst: meta.rwnd_rtx_count;
    output_value: alu_lo;
    output_predicate: true;
}

action read_update_rwnd_rtx_count () {
    read_update_rwnd_rtx_count_alu.execute_stateful_alu(meta.conn_idx);
}


table read_update_rwnd_rtx_count_tab {
    actions {
        read_update_rwnd_rtx_count;
    }

    default_action  : read_update_rwnd_rtx_count;
    size : 1;
}

/*===============================================================================================*/
/* reroute bit*/

register rwnd_reroute_bit {
  width: 8;
  instance_count: MAX_CONN_TABLE_SIZE;
}


blackbox stateful_alu read_update_reroute_bit_alu {
    reg : rwnd_reroute_bit;

    condition_lo: meta.rwnd_rtx_count > DUPACK_THRESH;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: 1;

    output_dst: meta.rwnd_reroute_bit;
    output_value: alu_lo;
    output_predicate: true;
}

action read_update_reroute_bit () {
    read_update_reroute_bit_alu.execute_stateful_alu(meta.conn_idx);
}


table read_update_reroute_bit_tab {
    actions {
        read_update_reroute_bit;
    }

    default_action  : read_update_reroute_bit;
    size : 1;
}

blackbox stateful_alu read_reroute_bit_alu {
    reg : rwnd_reroute_bit;

    output_dst: meta.rwnd_reroute_bit;
    output_value: register_lo;
    output_predicate: true;
}

action read_reroute_bit () {
    read_reroute_bit_alu.execute_stateful_alu(meta.conn_idx);
}

@pragma stage 5
table read_reroute_bit_tab {
    actions {
        read_reroute_bit;
    }

    default_action  : read_reroute_bit;
    size : 1;
}

register rwnd_pkt_count {
  width: 8;
  instance_count: MAX_CONN_TABLE_SIZE;
}


blackbox stateful_alu read_update_rwnd_pkt_count_alu {
    reg : rwnd_pkt_count;

    condition_lo: register_lo == RWND_BATCH;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: 0;

    update_lo_2_predicate: not condition_lo;
    update_lo_2_value: register_lo + 1;

    output_dst: meta.rwnd_pkt_count;
    output_value: alu_lo;
    output_predicate: true;
}

action read_update_rwnd_pkt_count () {
    read_update_rwnd_pkt_count_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_rwnd_pkt_count_tab {
    actions {
        read_update_rwnd_pkt_count;
    }

    default_action  : read_update_rwnd_pkt_count;
    size : 1;
}

/*===============================================================================================*/
/* reroute bit*/

register rwnd_enlarge_bit {
  width: 8;
  instance_count: MAX_CONN_TABLE_SIZE;
}


blackbox stateful_alu read_update_enlarge_bit_alu {
    reg : rwnd_enlarge_bit;

    condition_lo: meta.rwnd_pkt_count == RWND_BATCH;
    condition_hi: register_lo == 0;

    update_lo_1_predicate: condition_hi and condition_lo;
    update_lo_1_value: 1;

    update_lo_2_predicate: not condition_hi and condition_lo;
    update_lo_2_value: 0;

    output_dst: meta.rwnd_enlarge_bit;
    output_value: alu_lo;
    output_predicate: true;
}

action read_update_enlarge_bit () {
    read_update_enlarge_bit_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_enlarge_bit_tab {
    actions {
        read_update_enlarge_bit;
    }

    default_action  : read_update_enlarge_bit;
    size : 1;
}

field_list tcp_checksum_list {
    ipv4.srcAddr;
    ipv4.dstAddr;
    8'0;
    ipv4.protocol;
    meta.l4_len;
    tcp.srcPort;
    tcp.dstPort;
    tcp.seqNo;
    tcp.ackNo;
    tcp.dataOffset;
    tcp.res;
    tcp.flags;
    tcp.window;
    tcp.urgentPtr;
    payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    update tcp_checksum if (meta.update_tcp_checksum == 1);
}


action set_checksum() {
    modify_field (meta.update_tcp_checksum, 1);
}

table set_checksum_tab {
    actions {
        set_checksum;
    }

    default_action : set_checksum;
    size : 1;
}

/*===============================================================================================*/
/*Naive defense*/

action get_rwnd_shrinked (rwnd_lowerbound) {
    modify_field(meta.window_shrinked, rwnd_lowerbound);
}
table get_rwnd_shrinked_tab{
    reads {
        tcp.window : range;
    }

    actions {
        get_rwnd_shrinked;
    }
    default_action  : get_rwnd_shrinked;
    size : 1024;
}
#endif