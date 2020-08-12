#!/bin/bash

#http://xmodulo.com/measure-packets-per-second-throughput-high-speed-network-interface.html

INTERVAL="1"  # update interval in seconds

if [ -z "$1" ]; then
        echo
        echo usage: $0 [network-interface]
        echo
        echo e.g. $0 eth0
        echo
        exit
fi

IF=$1

while true
do
        R1=`cat /sys/class/net/$1/statistics/rx_bytes`
        T1=`cat /sys/class/net/$1/statistics/tx_bytes`
        sleep $INTERVAL
        R2=`cat /sys/class/net/$1/statistics/rx_bytes`
        T2=`cat /sys/class/net/$1/statistics/tx_bytes`
        TBPS=`expr $T2 - $T1`
        RBPS=`expr $R2 - $R1`
        TKBitPS=`expr $TBPS / 1000 \* 8`
        RKBitPS=`expr $RBPS / 1000 \* 8`
        echo "TX $1: $TKBitPS Kbps RX $1: $RKBitPS Kbps"
done
