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

        tstamp_ipd32:  32;

        /* for rwnd channels */
        rwnd_last_ack: 32;
        rwnd_dupack_count: 8;
        rwnd_rtx_count: 8;
        rwnd_pkt_count: 8;
        rwnd_reroute_bit: 8;
        rwnd_enlarge_bit: 8;
        update_tcp_checksum: 1;
        window_shrinked: 16;
        window_enlarged: 16;
        l4_len: 16; // for checksum


        // The register index matched in the connection table
        // check the bits when change table size
        conn_idx: 24;
        // mark conn table hit or miss, 1 is hit, 0 is miss
        // conn_hit_state: 1;
        // 1 is conn entry, 2 is ipd
        digest_type: 2;
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

header ethernet_t ethernet;
header ipv4_t     ipv4;
header tcp_t      tcp;
metadata  custom_metadata_t meta;

#endif