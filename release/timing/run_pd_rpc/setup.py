__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'

import time
import atexit
import pdb
import threading

execscript("netwarden.py")

def do_learn():
	p4_pd.digest_fields_register()
	print "Learning receiver registered, ready to start receiving connections"
	while True:
	    try:
	        msg = learning_notifications_get()
	        learning_notifications_process(msg)
	    except Exception as e:
	    	print "Learning broken: ", e
	        break

	    time.sleep(1/1000.0)

@atexit.register
def learn_unregister():
    global digest
    try:
        p4_pd.digest_fields_digest_notify_ack(digest.msg_ptr)
        p4_pd.digest_fields_deregister()
    except:
        pass

def learning_notifications_get():
    global digest
    try:
        digest = p4_pd.digest_fields_get_digest()
    except Exception as e:
        print "Got Exception ", e
        return []
    if digest.msg != []:
        # print "Found digest message"
        # This prevents a crash in learn_unregister, by ensuring that it
        # will not attempt to ack the same msg_ptr twice (DRV-1108)
        msg_ptr = digest.msg_ptr
        digest.msg_ptr = 0
        p4_pd.digest_fields_digest_notify_ack(msg_ptr)
    return digest.msg

def learning_notifications_process(msg):
    global netwarden
    ttl = 10*1000 # Change if needed
    conn_mgr.begin_txn(isAtomic=True)

    for m in msg:
        if m.ipv4_srcAddr == 0 or m.ipv4_dstAddr == 0 or m.tcp_srcPort == 0 or m.tcp_dstPort == 0:
            continue

        if m.meta_digest_type == 1:
            # print "meta_digest_type == 1"
            # print "receive a entry digest"
            netwarden.netwarden_add(m.ipv4_srcAddr, m.tcp_srcPort, m.ipv4_dstAddr, m.tcp_dstPort)

        elif m.meta_digest_type == 2:

            # print "meta_digest_type == 2"

            key = str(m.ipv4_srcAddr)+str(m.tcp_srcPort)+\
                  str(m.ipv4_dstAddr)+str(m.tcp_dstPort)
            #print "receive a ipd digest, count: "+str(len(list_key))
            netwarden.ipds[key].append(m.meta_tstamp_ipd32)
            list_key = netwarden.ipds.get(key)
            # do ks-test every 100 packets
            if(len(list_key) % 5 == 0):
                result = netwarden.do_kstest(list_key)
                # print "ks test result is " + str(result)

                # if malicious, add an entry to forward the packets to CPU
                if result == True:
                    # print "marking this flow as malicious!"
                    netwarden.add_entry_cpu(m.ipv4_srcAddr, m.tcp_srcPort, m.ipv4_dstAddr, m.tcp_dstPort)
        else:
            continue

    conn_mgr.commit_txn(hwSynchronous = True)




netwarden = netwarden()
netwarden.setup()

learning_t = threading.Thread(target=do_learn)

print "Sleeping before starting aging and learning threads..."
time.sleep(5)

learning_t.start()
learning_t.join()

