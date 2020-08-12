/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/


#ifndef CMIN_1ST_P4
#define CMIN_1ST_P4

#define CMIN_1ST_SIZE 65536

// 1 = 2^16 ns = 65 us
#define CMIN_1ST_BOUNDARY 0 // Use this for test purpose, this will regard every flow as malicious
#define CMIN_1ST_THRESH 1   // Use this for test purpose, this will regard every flow as malicious
#define CMIN_1ST_FREQ 200

//#define CMIN_1ST_BOUNDARY 1000 //65ms

/*===============================================================================================*/
/* read and update the cmin_1st_thresh*/

register cmin_1st_thresh {
    width: 16;
    instance_count: MAX_CONN_TABLE_SIZE;
}

blackbox stateful_alu read_update_cmin_1st_thresh_alu {
    reg : cmin_1st_thresh;

    condition_lo: register_lo == 0;
    condition_hi: meta.cmin_1st_ipd_count == CMIN_1ST_FREQ;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: CMIN_1ST_THRESH;

    update_lo_2_predicate: condition_hi;
    update_lo_2_value: register_lo+CMIN_1ST_THRESH;

    output_dst: meta.cmin_1st_thresh;
    output_value: register_lo;
    output_predicate: true;
}

action read_update_cmin_1st_thresh () {
    read_update_cmin_1st_thresh_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_cmin_1st_thresh_tab {
    actions {
      read_update_cmin_1st_thresh;
    }
    default_action: read_update_cmin_1st_thresh;
    size: 1;
}

/*===============================================================================================*/
/* read and update the cmin_1st_ipd_count*/

register cmin_1st_ipd_count {
    width: 16;
    instance_count: MAX_CONN_TABLE_SIZE;
}

blackbox stateful_alu read_update_cmin_1st_ipd_count_alu {
    reg : cmin_1st_ipd_count;

    // condition for writing to the register
    condition_lo: register_lo < CMIN_1ST_FREQ;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: register_lo + 1; //count++

    update_lo_2_predicate: not condition_lo;
    update_lo_2_value: 1;

    // output
    output_dst: meta.cmin_1st_ipd_count;
    output_value: register_lo;
    output_predicate: true;
}

action read_update_cmin_1st_ipd_count () {
    read_update_cmin_1st_ipd_count_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_cmin_1st_ipd_count_tab {
    actions {
      read_update_cmin_1st_ipd_count;
    }
    default_action: read_update_cmin_1st_ipd_count;
    size: 1;
}

/*===============================================================================================*/
/* Registers used for the first level count-min sketch */

/* left side and right side count-min registers*/

#define CMIN_1ST(SIDE, ID)                     \
register cmin_1st_##SIDE##_hash##ID {          \
    width: 32;                                 \
    instance_count: CMIN_1ST_SIZE;             \
}

CMIN_1ST(right, 1)
CMIN_1ST(right, 2)
CMIN_1ST(right, 3)

/*===============================================================================================*/
/* the count-min tables*/

field_list cmin_1st_hash_fields {
    tcp.srcPort;
    tcp.dstPort;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation cmin_1st_hash1_calc {
    input {cmin_1st_hash_fields;}
    algorithm : crc_16;
    output_width: 16;
}

field_list_calculation cmin_1st_hash2_calc {
    input {cmin_1st_hash_fields;}
    algorithm : crc_16_usb;
    output_width: 16;
}

field_list_calculation cmin_1st_hash3_calc {
    input {cmin_1st_hash_fields;}
    algorithm : crc_16_dnp;
    output_width: 16;
}

#define READ_UPDATE_CMIN_1ST_RIGHT(SIDE, ID)                                                    \
blackbox stateful_alu read_update_cmin_1st_##SIDE##_hash##ID##_alu {                            \
    reg : cmin_1st_##SIDE##_hash##ID;                                                           \
                                                                                                \
    condition_lo: meta.tstamp_ipd32 > CMIN_1ST_BOUNDARY;                                        \
    condition_hi: meta.cmin_1st_ipd_count != 0;                                                 \
    update_lo_1_predicate: condition_lo and condition_hi;                                       \
    update_lo_1_value: register_lo + 1;                                                         \
                                                                                                \
    output_predicate: true;                                                                     \
    output_dst: meta.cmin_1st_##SIDE##_hash##ID;                                                \
    output_value: register_lo;                                                                  \
                                                                                                \
}                                                                                               \
                                                                                                \
action read_update_cmin_1st_##SIDE##_hash##ID() {                                               \
    read_update_cmin_1st_##SIDE##_hash##ID##_alu.execute_stateful_alu_from_hash(cmin_1st_hash##ID##_calc);   \
}                                                                                               \
table read_update_cmin_1st_##SIDE##_hash##ID##_tab {                                            \
    actions {                                                                                   \
      read_update_cmin_1st_##SIDE##_hash##ID;                                                   \
    }                                                                                           \
    default_action: read_update_cmin_1st_##SIDE##_hash##ID;                                     \
    size: 1;                                                                                    \
}

READ_UPDATE_CMIN_1ST_RIGHT(right, 1)
READ_UPDATE_CMIN_1ST_RIGHT(right, 2)
READ_UPDATE_CMIN_1ST_RIGHT(right, 3)

/*===============================================================================================*/
/* get min of the sketch*/

action comp_cmin_1st_step1 () {
    min(meta.cmin_1st_right, meta.cmin_1st_right_hash1, meta.cmin_1st_right_hash2);
}

table comp_cmin_1st_step1_tab {
    actions {
      comp_cmin_1st_step1;
    }
    default_action: comp_cmin_1st_step1;
    size: 1;
}


action comp_cmin_1st_step2 () {
    min(meta.cmin_1st_right, meta.cmin_1st_right, meta.cmin_1st_right_hash3);
}

table comp_cmin_1st_step2_tab {
    actions {
      comp_cmin_1st_step2;
    }
    default_action: comp_cmin_1st_step2;
    size: 1;
}


/*===============================================================================================*/
/* check whether reach out the threshold*/
action check_cmin_1st () {
    min(meta.cmin_1st_res, meta.cmin_1st_right, meta.cmin_1st_thresh);
}

table check_cmin_1st_tab {
    actions {
      check_cmin_1st;
    }
    default_action: check_cmin_1st;
    size: 1;
}

// tstamp of the last full packet from the server side
register timing_mal_bit {
  width: 16;
  instance_count: MAX_CONN_TABLE_SIZE;
}

blackbox stateful_alu read_update_timing_mal_bit_alu {
    reg : timing_mal_bit;

    condition_lo: meta.cmin_1st_res == CMIN_1ST_THRESH;
    update_lo_1_predicate: condition_lo;
    update_lo_1_value: 1;

    output_predicate: true;
    output_dst: meta.timing_mal_bit;
    output_value: register_lo;
}

action read_update_timing_mal_bit () {
    read_update_timing_mal_bit_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_timing_mal_bit_tab {
    actions {
      read_update_timing_mal_bit;
    }
    size: 1;
}

#endif
