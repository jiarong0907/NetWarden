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

        // the ipd
        tstamp_ipd32:  32;

        // the tstamp for last full ack packet from the server side
        fack_ts: 32;

        // the highwater for incoming packets
        in_highwater: 32;

        // 32 bit version of totalLen in ipv4
        my_totallen: 32;
        // 32 bit version of dataOffset in tcp
        my_dataoffset: 32;
        // my_dataoffset << 2
        my_dataoffset_shifted: 32;

        pkt_count: 16;
        min_pkt_count_512: 16;
        min_pkt_count_5: 16;
        covert_data: 32;
        min_flag_pack_11: 32;
        last_ack: 32;
        tcp_len: 32;
        min_last_ack: 32;
        fin_state: 8;

        // the last full ack number, used in rewinding
        fack: 32;

        // wait time, = meta.tstamp - meta.fack_ts
        wait_time: 32;
        pack_rand: 32;
        pack_rand_bit4: 4;

        l4_len: 16;
        update_tcp_checksum: 1;

        // the min(waiting time, TIMEOUT)
        min_wait_timeout: 32;


        // 0 means full ack pkts, otherwise partial ack pkts
        flag_pack: 32;
        fin: 8;
        syn: 8;


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