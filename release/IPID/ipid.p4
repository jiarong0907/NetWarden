/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/

#ifdef __TARGET_TOFINO__
  #include <tofino/constants.p4>
  #include <tofino/intrinsic_metadata.p4>
  #include <tofino/primitives.p4>
  #include <tofino/stateful_alu_blackbox.p4>
#else
  #error This program is intended to compile for Tofino P4 architecture only
#endif

#define PORT_SERVER 48
#define PORT_CLIENT 0

/*===============================================================================================*/
/* headers */

header_type ethernet_t {
    fields {
        dstAddr         : 48;
        srcAddr         : 48;
        etherType       : 16;
    }
}

header_type ipv4_t {
    fields {
        version         : 4;
        ihl             : 4;
        diffserv        : 8;
        totalLen        : 16;
        identification  : 16;
        flags           : 3;
        fragOffset      : 13;
        ttl             : 8;
        protocol        : 8;
        hdrChecksum     : 16;
        srcAddr         : 32;
        dstAddr         : 32;
    }
}

header_type tcp_t {
    fields {
        srcPort         : 16;
        dstPort         : 16;
        seqNo           : 32;
        ackNo           : 32;
        dataOffset      : 4;
        res             : 4;
        flags           : 8;
        window          : 16;
        checksum        : 16;
        urgentPtr       : 16;
    }
}

header_type custom_metadata_t {
    fields {
        update_ipv4_checksum: 1; // The bit indicating for updating IP checksum
    }
}

header ethernet_t ethernet;
header ipv4_t     ipv4;
header tcp_t      tcp;
metadata  custom_metadata_t meta;

/*===============================================================================================*/
/* parsers */

parser start {
    extract(ethernet);
    return select(ethernet.etherType) {
        0x0800 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return parse_tcp;
}

parser parse_tcp {
    extract(tcp);
    return ingress;
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

// update IP checksum
calculated_field ipv4.hdrChecksum {
    update ipv4_chksum_calc if (meta.update_ipv4_checksum == 1);
}

/*===============================================================================================*/
/* hard-code forwarding table */
action nhop_client_set( ) {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, PORT_CLIENT);
}

table nhop_client_tab {
    actions {
        nhop_client_set;
    }
    default_action  : nhop_client_set;
    size : 1;
}

action nhop_server_set( ) {
  modify_field(ig_intr_md_for_tm.ucast_egress_port, PORT_SERVER);
}

table nhop_server_tab {
    actions {
        nhop_server_set;
    }
    default_action  : nhop_server_set;
    size : 1;
}

/*===============================================================================================*/
/* mitigation */

// normalize IPID to remove covert storage channels
action normalize_ipid( ) {
  modify_field (ipv4.identification, 1023);
  // need to update the IP checksum
  modify_field (meta.update_ipv4_checksum, 1);
}

table normalize_ipid_tab {
    actions {
        normalize_ipid;
    }
    default_action  : normalize_ipid;
    size : 1;
}


control ingress{
    if (ig_intr_md.ingress_port == PORT_SERVER) {
        apply (normalize_ipid_tab);
        apply (nhop_client_tab);
    } else if(ig_intr_md.ingress_port == PORT_CLIENT) {
        apply (nhop_server_tab);
    }
}
