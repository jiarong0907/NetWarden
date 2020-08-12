## Covert timing channels


### Attack description
The attacker encodes data into the packet timing---using large inter-packet delays (IPDs) to encode 1s and using small ones to encode 0s.

### Defense description
#### Naive defense
The naive defense monitors the number of large IPDs in the data plane. If it reaches out a threshold, the IPDs will be sent to the switch control plane for KS-Test. If the flow is marked as malicious, the flow will be sent to the cache to destroy the timing pattern. The cache will incurs delay to the RTT, so the sending rate will decrease.

#### NetWarden defense
NetWarden uses the same way to detect and mitigate covert timing channels, but it also uses ACK booster to improve the performance.

### Experiment setup
- Switch: Wedge 100BF-32X Tofino switch.
- Barefoot SDE: `bf-sde-8.8.0`
- Host OS: Ubuntu 18.04
- TCP congestion control: reno/vegas/westwood




### Run the code

**Step 1:** Build and run the P4 program:
```
cd ~/bf-sde-8.8.0
source set_sde.bash
./p4_build.sh /home/jiarong/NetWarden/release/timing/timing.p4
./run_switchd.sh -p timing
```


**Step 2:** Enable all ports of the switch.
```
ucli
pm
port-add -/- 25G NONE
port-enb -/-
```


**Step 3:** Run control plane program:
```
# Run in another terminal in the switch
cd ~/bf-sde-8.8.0
source set_sde.bash
~/tools/run_pd_rpc.py -p timing /home/jiarong/NetWarden/release/timing/run_pd_rpc/setup.py
```


**Step 4:** Configure the TCP congestion control algorithm for both the server and the client:
```
sysctl net.ipv4.tcp_available_congestion_control
echo "vegas/westwood/cubic/reno" > sudo tee /proc/sys/net/ipv4/tcp_congestion_control
or sudo sysctl net.ipv4.tcp_congestion_control=vegas/westwood/cubic/reno
cat /proc/sys/net/ipv4/tcp_congestion_control
```



**Step 5:** Compile and run the cache:
```
cd reno_cache/vegas_cache/west_cache
gcc -O3 echo.c mytimer.c conn.c cache.c -lpcap -lpthread

sudo ./a.out -n -b 5 -w 30 -l 0.1     # Reno naive defense
sudo ./a.out -b 15 -r 8 -p 8 -l 0.1   # Reno NetWarden

sudo ./a.out -n -b 25 -w 100          # Vegas naive defense
sudo ./a.out -b 15 -r 8 -p 8          # Vegas NetWarden

sudo ./a.out -n -b 5 -w 30 -l 0.1     # Westwood naive defense
sudo ./a.out -b 15 -r 8 -p 8 -l 0.1   # Westwood NetWarden
```



**Step 6:** In the server side:
```
sudo python3.7 server.py
```


**Step 7:** In the client side, open another terminal and simulate the network condition:
```
# setup_net_rate.py is under /NetWarden/release/tools/
# no defense
sudo python setup_net_rate.py 10 1 0.1 add  # Reno
sudo python setup_net_rate.py 20 5 0.1 add  # Vegas
sudo python setup_net_rate.py 15 3 0.1 add  # Westwood

# for naive and netwarden
sudo python setup_net_rate.py 10 1 0 add  # Reno
sudo python setup_net_rate.py 20 5 0 add  # Vegas
sudo python setup_net_rate.py 15 3 0 add  # Westwood
```

**Step 8:** In the client side, open another terminal and start the connection:
```
sudo python3.7 client.py
```

**Step 9:** Observe the decoding rate of the covert channel printed by the client. Sometimes, the error rate for no defense is very high, this is caused by great network variation. You can enlarge the IPD to remove the influence of the network variance or you can remove all network variance.


**Step 10:** Remove the network configurations:
```
sudo python setup_net_rate.py 10 1 0 del  # Reno
sudo python setup_net_rate.py 20 5 0 del  # Vegas
sudo python setup_net_rate.py 15 3 0 del  # Westwood
```

**To observe the TCP sending rate:**
In the client side, you can capture packets using tcpdump and compute the sending rate yourself:
```
sudo tcpdump -G 60 -W 1 -w timing.pcap
```

or you can use our simple netspeed script to see the real time sending rate by:
```
# The script is named netspeed.sh under /NetWarden/release/tools/.
sudo bash netspeed.sh
```
