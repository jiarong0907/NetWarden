#!/bin/bash

set -e
set -x


for IF in ens3f0 ens3f1 ens6f0 ens6f1
do
   # enable promisc mode
   sudo ifconfig $IF promisc

   # disable all offload features
   sudo ethtool -K $IF tso off
   sudo ethtool -K $IF gso off
   sudo ethtool -K $IF gro off
   sudo ethtool -K $IF tx off
   sudo ethtool -K $IF rx off
   sudo ethtool -K $IF sg off
done

# disable sack
sudo sysctl net.ipv4.tcp_sack=0