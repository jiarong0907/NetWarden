/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/


#ifndef PARSER_P4
#define PARSER_P4

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

#endif