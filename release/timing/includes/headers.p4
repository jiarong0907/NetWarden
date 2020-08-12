/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/



#ifndef HEADER_P4
#define HEADER_P4

/*===============================================================================================*/
/* headers */

header_type custom_metadata_t {
    fields {

        // higher 32 bits of ingress timestamp
        tstamp: 32;

        // old timestamps
        tstamp_old:  32;

        // last_rtt_tstamp
        tstamp_rtt:  32;
        rtt_32:  32;
        rtt_16:  16;
        seq_16:  16;
        ack_16:  16;


        // the ipd
        tstamp_ipd32:  32;

        // the highwater for incoming packets
        highwater: 32;
        highwater_16: 16;

        // 32 bit version of totalLen in ipv4
        my_totallen: 32;
        // 32 bit version of dataOffset in tcp
        my_dataoffset: 32;
        // my_dataoffset << 2
        my_dataoffset_shifted: 32;


        new_round_bit: 8;
        data_cpu: 8;


        /* for timing channels*/
        // The number of ipds we have stored
        // check the bits when change the number of ipds we want to maintain
        cmin_1st_ipd_count: 16;

        // The register index matched in the connection table
        // check the bits when change table size
        conn_idx: 24;
        // mark conn table hit or miss, 1 is hit, 0 is miss
        // conn_hit_state: 1;
        // 1 is conn entry, 2 is ipd
        digest_type: 2;

        cmin_1st_right_hash1: 16;
        cmin_1st_right_hash2: 16;
        cmin_1st_right_hash3: 16;
        cmin_1st_right: 16;
        cmin_1st_res: 16;

        // 1 means the connection might be malicious
        timing_mal_bit: 16;

        /* boundary for sketch */
        cmin_1st_thresh: 16;

        l4_len: 16;
        update_ipv4_checksum: 1;
    }
}

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}


header_type ipv4_t {
    fields {
        version        : 4;
        ihl            : 4;
        diffserv       : 8;
        totalLen       : 16;
        identification : 16;
        flags          : 3;
        fragOffset     : 13;
        ttl            : 8;
        protocol       : 8;
        hdrChecksum    : 16;
        srcAddr        : 32;
        dstAddr        : 32;
    }
}

header_type tcp_t {
    fields {
        srcPort     : 16;
        dstPort     : 16;
        seqNo       : 32;
        ackNo       : 32;
        dataOffset  : 4;
        res         : 4;
        flags       : 8;
        window      : 16;
        checksum    : 16;
        urgentPtr   : 16;
    }
}

/* headers for packets to the control plane */
header_type cpu_t {
    fields {
        pktType : 2;
        cache_size: 16;
    }
}


header ethernet_t ethernet;
header ipv4_t     ipv4;
header tcp_t      tcp;
metadata  custom_metadata_t meta;

#endif
