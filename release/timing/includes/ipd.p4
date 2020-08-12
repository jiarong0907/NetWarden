/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/




#ifndef IPD_P4
#define IPD_P4

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
/* compute the ipd*/

action compute_ipd () {
    subtract(meta.tstamp_ipd32, meta.tstamp, meta.tstamp_old);
}

table compute_ipd_tab {
    actions {
      compute_ipd;
    }
    default_action: compute_ipd;
    size: 1;
}

/*===============================================================================================*/
/* the timestamp tables*/

// timestamps
register ts {
    width: 32;
    instance_count: MAX_CONN_TABLE_SIZE;
}

// read and update the conn timestamp: low32
blackbox stateful_alu read_update_ts_alu {
    reg : ts;

    // condition for writing to the register
    condition_lo: true;

    update_lo_1_predicate: condition_lo;
    update_lo_1_value: meta.tstamp;

    // output
    output_dst: meta.tstamp_old;
    output_value: register_lo;
    output_predicate: condition_lo;
}

action read_update_ts () {
    read_update_ts_alu.execute_stateful_alu(meta.conn_idx);
}

table read_update_ts_tab {
    actions {
      read_update_ts;
    }
    default_action: read_update_ts;
    size: 1;
}

#endif