/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/



#ifndef RTT_P4
#define RTT_P4

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
    add(meta.highwater, meta.my_totallen, tcp.seqNo);
}

table add_totallen_seq_tab {
    actions {
        add_totallen_seq;
    }

    default_action  : add_totallen_seq;
    size : 1;
}

action minus_dataoffset () {
    subtract_from_field(meta.highwater, meta.my_dataoffset_shifted);
}

table minus_dataoffset_tab {

    actions {
        minus_dataoffset;
    }

    default_action  : minus_dataoffset;
    size : 1;
}

register new_round_bit {
  width: 8;
  instance_count: MAX_CONN_TABLE_SIZE;
}

blackbox stateful_alu read_update_new_round_bit_data_alu {
    reg : new_round_bit;

    condition_lo: register_lo == 0;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: 1;

    output_dst: meta.new_round_bit;
    output_value: register_lo;
    output_predicate: true;
}

action read_update_new_round_bit_data () {
    read_update_new_round_bit_data_alu.execute_stateful_alu(meta.conn_idx);
}
// @pragma stage 8
table read_update_new_round_bit_data_tab {
    actions {
        read_update_new_round_bit_data;
    }

    default_action  : read_update_new_round_bit_data;
    size : 1;
}

blackbox stateful_alu read_update_new_round_bit_ack_alu {
    reg : new_round_bit;

    update_lo_1_predicate: true;
    update_lo_1_value: 0;

    output_dst: meta.new_round_bit;
    output_value: register_lo;
    output_predicate: true;
}

action read_update_new_round_bit_ack () {
    read_update_new_round_bit_ack_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_new_round_bit_ack_tab {
    actions {
        read_update_new_round_bit_ack;
    }

    default_action  : read_update_new_round_bit_ack;
    size : 1;
}

field_list highwater_32 {
    meta.highwater;
}

field_list_calculation highwater_low16 {
    input {
      highwater_32;
    }
    algorithm : identity_lsb;
    output_width: 16;
}

action split_highwater_low16 () {
    modify_field_with_hash_based_offset(meta.highwater_16, 0, highwater_low16, 65536);
}

table split_highwater_low16_tab {
    actions{
      split_highwater_low16;
    }
    default_action: split_highwater_low16;
    size: 1;
}

action get_highwater () {
    subtract_from_field (meta.highwater, 20);
}

table get_highwater_tab {
    actions {
        get_highwater;
    }

    default_action  : get_highwater;
    size : 1;
}

register rtt_ts {
  width: 32;
  instance_count: 65536;
}

// read last rtt timestamp for ack packets
blackbox stateful_alu read_rtt_tstamp_alu {
    reg : rtt_ts;

    output_dst: meta.tstamp_rtt;
    output_value: register_lo;
    output_predicate: true;
}

action read_rtt_tstamp () {
    read_rtt_tstamp_alu.execute_stateful_alu(meta.ack_16);
}

@pragma stage 5
table read_rtt_tstamp_tab {
    actions {
      read_rtt_tstamp;
    }
    default_action: read_rtt_tstamp;
    size: 1;
}


// update last rtt timestamp for data packets
blackbox stateful_alu update_rtt_tstamp_alu {
    reg : rtt_ts;

    update_lo_1_predicate: true;
    update_lo_1_value: meta.tstamp;
}

action update_rtt_tstamp () {
    update_rtt_tstamp_alu.execute_stateful_alu(meta.highwater_16);
}

table update_rtt_tstamp_tab {
    actions {
      update_rtt_tstamp;
    }
    default_action: update_rtt_tstamp;
    size: 1;
}

action filter_cpu_data_pkt(flag) {
    modify_field(meta.data_cpu, flag);
}

table filter_cpu_data_pkt_tab {
    reads {
        ipv4.dstAddr: exact;
    }
    actions {
        filter_cpu_data_pkt;
    }
    default_action: nop;
    size : FORWARDING_TABLE_SIZE;
}

action cal_rtt () {
    subtract (meta.rtt_32, meta.tstamp, meta.tstamp_rtt);
}

table cal_rtt_tab {
    actions {
      cal_rtt;
    }
    default_action: cal_rtt;
    size: 1;
}

action put_rtt () {
    modify_field(ipv4.identification, meta.rtt_16);
    // modify_field (ipv4.identification, 1023);
}

table put_rtt_tab {
    actions {
      put_rtt;
    }
    default_action: put_rtt;
    size: 1;
}

// Use high 16-bit of the 32 bits of rtt
field_list rtt_32 {
    meta.rtt_32;
}

field_list_calculation rtt_low16 {
    input {
      rtt_32;
    }
    algorithm : identity_lsb;
    output_width: 16;
}

action split_rtt_low16 () {
    modify_field_with_hash_based_offset(meta.rtt_16, 0, rtt_low16, 65536);
}

table split_rtt_low16_tab {
    actions{
      split_rtt_low16;
    }
    default_action: split_rtt_low16;
    size: 1;
}

// Use low 16-bit of the 32 bits of seq
field_list seq_32 {
    tcp.seqNo;
}

field_list_calculation seq_low16 {
    input {
      seq_32;
    }
    algorithm : identity_lsb;
    output_width: 16;
}

action split_seq_low16 () {
    modify_field_with_hash_based_offset(meta.seq_16, 0, seq_low16, 65536);
}

table split_seq_low16_tab {
    actions{
      split_seq_low16;
    }
    default_action: split_seq_low16;
    size: 1;
}


// Use low 16-bit of the 32 bits of ack
field_list ack_32 {
    tcp.ackNo;
}

field_list_calculation ack_low16 {
    input {
      ack_32;
    }
    algorithm : identity_lsb;
    output_width: 16;
}

action split_ack_low16 () {
    modify_field_with_hash_based_offset(meta.ack_16, 0, ack_low16, 65536);
}

table split_ack_low16_tab {
    actions{
      split_ack_low16;
    }
    default_action: split_ack_low16;
    size: 1;
}

field_list ipv4_field_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}


field_list_calculation ipv4_chksum_calc {
    input {
        ipv4_field_list;
    }
    algorithm : csum16;
    output_width: 16;
}

calculated_field ipv4.hdrChecksum {
    update ipv4_chksum_calc;
}

#endif