/*==============================================================================================
__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'
==============================================================================================*/

#ifndef CONST_P4
#define CONST_P4

/*===============================================================================================*/
/* constants*/
#define MAX_CONN_TABLE_SIZE 100000
#define FORWARDING_TABLE_SIZE 1000


#define PORT_CPU 192
// assumption: port 0 is the remote client;
#define PORT_SERVER 48
#define PORT_CLIENT 0


#define DUPACK_THRESH 5

#define RWND_BATCH 2


#define CPU_IN  192   // bf_pci0 in switch control plane
#define CPU_OUT 192   // bf_pci0 in switch control plane


#endif