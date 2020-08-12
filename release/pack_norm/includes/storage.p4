/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/


#ifndef STORAGE_P4
#define STORAGE_P4

/*===============================================================================================*/
/* obtain timestamps */

// Use high 32-bit tstamp of the full 48 bits
field_list tstamp {
    _ingress_global_tstamp_;
}

field_list_calculation tstamp_high32 {
    input {
      tstamp;
    }
    algorithm : identity_msb;
    output_width: 32;
}

action split_tstamp_high32 () {
    modify_field_with_hash_based_offset(meta.tstamp, 0, tstamp_high32, 4294967296);
}

table split_tstamp_high32_tab {
    actions{
      split_tstamp_high32;
    }
    default_action: split_tstamp_high32;
    size: 1;
}

/*===============================================================================================*/
/* read and update highwater*/

// highwater: the number of bytes received from external node
register in_highwater {
  width: 32;
  instance_count: MAX_CONN_TABLE_SIZE;
}

// for high water mark from external client:
blackbox stateful_alu update_in_highwater_alu {
    reg : in_highwater;

    condition_lo: register_lo < meta.in_highwater - 20;

    update_lo_1_predicate: condition_lo;
    //update_lo_1_value: (ipv4.totalLen - 20 - (tcp.dataOffset << 2)) + tcp.seqNo;
    update_lo_1_value: meta.in_highwater - 20;
}

action update_in_highwater () {
    update_in_highwater_alu.execute_stateful_alu(meta.conn_idx);
}

@pragma stage 5
table update_in_highwater_tab {

    actions {
        update_in_highwater;
    }

    default_action  : update_in_highwater;
    size : 1;
}

blackbox stateful_alu read_in_highwater_alu {
    reg : in_highwater;

    output_dst: meta.in_highwater;
    output_value: register_lo;
    output_predicate: true;
}

action read_in_highwater () {
    read_in_highwater_alu.execute_stateful_alu(meta.conn_idx);
}

@pragma stage 5
table read_in_highwater_tab {
    actions {
        read_in_highwater;
    }

    default_action  : read_in_highwater;
    size : 1;
}

/*===============================================================================================*/
/* compute data size*/

field_list totallen_list {
    ipv4.totalLen;
}

field_list_calculation totallen_to_32 {
    input {
      totallen_list;
    }
    algorithm : identity_lsb;
    output_width: 16;
}

action convert_totallen_to_32 () {
    modify_field_with_hash_based_offset(meta.my_totallen, 0, totallen_to_32, 65536);
}

table convert_totallen_to_32_tab {
    actions{
      convert_totallen_to_32;
    }
    default_action: convert_totallen_to_32;
    size: 1;
}


field_list dataoffset_list {
    tcp.dataOffset;
}

field_list_calculation dataoffset_to_32 {
    input {
      dataoffset_list;
    }
    algorithm : identity_lsb;
    output_width: 4;
}

action convert_dataoffset_to_32 () {
    modify_field_with_hash_based_offset(meta.my_dataoffset, 0, dataoffset_to_32, 16);
}

table convert_dataoffset_to_32_tab {
    actions{
      convert_dataoffset_to_32;
    }
    default_action: convert_dataoffset_to_32;
    size: 1;
}


action shift_dataoffset () {
    shift_left(meta.my_dataoffset_shifted, meta.my_dataoffset, 2);
}

table shift_dataoffset_tab {

    actions {
        shift_dataoffset;
    }

    default_action  : shift_dataoffset;
    size : 1;
}

action add_totallen_seq () {
    add(meta.in_highwater, meta.my_totallen, tcp.seqNo);
}

table add_totallen_seq_tab {
    actions {
        add_totallen_seq;
    }

    default_action  : add_totallen_seq;
    size : 1;
}

action minus_dataoffset () {
    subtract_from_field(meta.in_highwater, meta.my_dataoffset_shifted);
    subtract (meta.tcp_len, meta.my_totallen, meta.my_dataoffset_shifted);
    //subtract (meta.tcp_len, ipv4.totalLen, meta.ipv4_len);
}

table minus_dataoffset_tab {

    actions {
        minus_dataoffset;
    }

    default_action  : minus_dataoffset;
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
    //tcp.checksum;
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


/*===============================================================================================*/
/* check whether it is a partial ack*/

// used to skip the case where in_highwater = 0 because the conn entry has not been installed
action skip() {
    modify_field(meta.flag_pack, 0);
}

action check_pack() {
    subtract(meta.flag_pack, meta.in_highwater, tcp.ackNo);
}

table check_pack_tab {
    reads{
        meta.in_highwater: exact;
    }
    actions {
        skip;
        check_pack;
    }

    default_action  : check_pack;
    size : 2;
}

/*===============================================================================================*/
/* read fack_ts when it is not a partial ack, otherwise update*/

// tstamp of the last full packet from the server side
register fack_ts {
  width: 32;
  instance_count: MAX_CONN_TABLE_SIZE;
}

// set the fack_ts to current tstamp
blackbox stateful_alu read_update_fack_ts_alu {
    reg : fack_ts;

    //condition_lo: ig_intr_md.ingress_port != PORT_IN;
    condition_hi: meta.flag_pack != 0;

    // reset the tstamp if it is a full ack packet
    update_lo_1_predicate: not condition_hi;
    update_lo_1_value: meta.tstamp;

    output_dst: meta.fack_ts;
    output_value: register_lo;
    output_predicate: condition_hi;
}

action read_update_fack_ts() {
    read_update_fack_ts_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_fack_ts_tab {
    actions {
        read_update_fack_ts;
    }

    default_action  : read_update_fack_ts;
    size : 1;
}

/*===============================================================================================*/
/* compute waiting time and get the min of waiting time and TIMEOUT*/

action compute_wait_time () {
    subtract(meta.wait_time, meta.tstamp, meta.fack_ts);
}

table compute_wait_time_tab {

    actions {
        compute_wait_time;
    }

    default_action  : compute_wait_time;
    size : 1;
}

action compute_min_wait_timeout () {
    min(meta.min_wait_timeout, meta.wait_time, TIMEOUT);
}

table compute_min_wait_timeout_tab {

    actions {
        compute_min_wait_timeout;
    }

    default_action  : compute_min_wait_timeout;
    size : 1;
}

/*===============================================================================================*/
/* read fack when it is not a pack, othersize update*/

// last full ack number, used in rewinded ack packet
register fack {
  width: 32;
  instance_count: MAX_CONN_TABLE_SIZE;
}

blackbox stateful_alu read_update_fack_alu {
    reg : fack;

    condition_lo: meta.flag_pack != 0;

    update_lo_1_predicate: not condition_lo;
    update_lo_1_value: tcp.ackNo;

    output_predicate: condition_lo;
    output_dst: meta.fack;
    output_value: register_lo;

}

action read_update_fack() {
    read_update_fack_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_fack_tab {
    actions {
        read_update_fack;
    }

    default_action  : read_update_fack;
    size : 1;
}


/*===============================================================================================*/
/* rewind packet*/
action generate_rewinded_fack() {
    modify_field (tcp.ackNo, meta.fack);
    modify_field (meta.update_tcp_checksum, 1);
}

table generate_rewinded_fack_tab {
    actions {
        generate_rewinded_fack;
    }

    default_action  : generate_rewinded_fack;
    size : 1;
}


action get_syn_bit_left () {
   shift_left(meta.syn, tcp.flags, 6);
   shift_left(meta.fin, tcp.flags, 7);
}

table get_syn_bit_left_tab {

    actions {
        get_syn_bit_left;
    }

    default_action  : get_syn_bit_left;
    size : 1;
}

action get_syn_bit_right () {
   shift_right(meta.syn, meta.syn, 7);
   shift_right(meta.fin, meta.fin, 7);
}

table get_syn_bit_right_tab {

    actions {
        get_syn_bit_right;
    }

    default_action  : get_syn_bit_right;
    size : 1;
}

register fin_state{
  width: 8;
  instance_count: MAX_CONN_TABLE_SIZE;
}

blackbox stateful_alu read_update_fin_state_alu {
    reg : fin_state;

    condition_lo: meta.fin == 1;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: 1;

    output_predicate: true;
    output_dst: meta.fin_state;
    output_value: alu_lo;
}

action read_update_fin_state() {
    read_update_fin_state_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_fin_state_tab {
    actions {
        read_update_fin_state;
    }

    default_action : read_update_fin_state;
    size : 1;
}

register last_ack{
  width: 32;
  instance_count: MAX_CONN_TABLE_SIZE;
}

blackbox stateful_alu read_update_last_ack_alu {
    reg : last_ack;

    //condition_lo: tcp.ackNo > register_lo;
    condition_lo: ig_intr_md.ingress_port == PORT_SERVER;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: tcp.ackNo;

    output_predicate: true;
    output_dst: meta.last_ack;
    output_value: register_lo;
}

action read_update_last_ack() {
    read_update_last_ack_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_last_ack_tab {
    actions {
        read_update_last_ack;
    }

    default_action : read_update_last_ack;
    size : 1;
}


action cal_min_last_ack() {
    min (meta.min_last_ack, tcp.ackNo, meta.last_ack);
}

table cal_min_last_ack_tab {
    actions {
        cal_min_last_ack;
    }

    default_action : cal_min_last_ack;
    size : 1;
}

register repeat_ack{
  width: 8;
  instance_count: MAX_CONN_TABLE_SIZE;
}

blackbox stateful_alu read_update_repeat_ack_alu {
    reg : repeat_ack;

    update_lo_1_predicate: true;
    update_lo_1_value: 0;

    output_predicate: true;
    output_dst: meta.repeat_ack;
    output_value: register_lo;
}

action read_update_repeat_ack() {
    read_update_repeat_ack_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_repeat_ack_tab {
    actions {
        read_update_repeat_ack;
    }

    default_action : read_update_repeat_ack;
    size : 1;
}

blackbox stateful_alu update_repeat_ack_alu {
    reg : repeat_ack;

    update_lo_1_predicate: true;
    update_lo_1_value: 1;
}

action update_repeat_ack() {
    update_repeat_ack_alu.execute_stateful_alu(meta.conn_idx);
}

table update_repeat_ack_tab {
    actions {
        update_repeat_ack;
    }

    default_action : update_repeat_ack;
    size : 1;
}

#endif