__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'


import collections
from scipy.stats import ks_2samp
from scipy.stats import kstest

CONN_TB_SIZE = 1000

train_data_path="/home/jiarong/NetWarden/release/timing/run_pd_rpc/ipd_list_normal_1-5.txt"

class netwarden():
    def __init__(self):
        self.free_idxs = []
        self.ipds = collections.defaultdict(list)
        self.conn_entries = [] # installed conn entries
        self.fpkt_entries = [] # installed fpkt entries
        self.train_data = self.get_data_from_list(train_data_path)

    def get_data_from_list(self, path):
      ret = []
      f = open(path)
      line = f.readline()
      while line:
            ret.append(int(line))
            line = f.readline()
      return ret

    def setup(self):
        clear_all()
        print "Setting up indexes and static nhop entries"
        for i in range(CONN_TB_SIZE):
            self.free_idxs.append(i)

        #nhop_ms = p4_pd.nhop_match_spec_t(32764)
        nhop_ms = p4_pd.nhop_match_spec_t(ipv4Addr_to_i32("192.168.0.1"))
        nhop_as = p4_pd.nhop_set_action_spec_t(48)
        p4_pd.nhop_table_add_with_nhop_set(nhop_ms, nhop_as)

        #nhop_ms = p4_pd.nhop_match_spec_t(32766)
        nhop_ms = p4_pd.nhop_match_spec_t(ipv4Addr_to_i32("192.168.0.2"))
        nhop_as = p4_pd.nhop_set_action_spec_t(0)
        p4_pd.nhop_table_add_with_nhop_set(nhop_ms, nhop_as)


        cpu_data_ms = p4_pd.filter_cpu_data_pkt_tab_match_spec_t(ipv4Addr_to_i32("192.168.0.1"))
        cpu_data_as = p4_pd.filter_cpu_data_pkt_action_spec_t(0)
        p4_pd.filter_cpu_data_pkt_tab_table_add_with_filter_cpu_data_pkt(cpu_data_ms, cpu_data_as)

        cpu_data_ms = p4_pd.filter_cpu_data_pkt_tab_match_spec_t(ipv4Addr_to_i32("192.168.0.2"))
        cpu_data_as = p4_pd.filter_cpu_data_pkt_action_spec_t(1)
        p4_pd.filter_cpu_data_pkt_tab_table_add_with_filter_cpu_data_pkt(cpu_data_ms, cpu_data_as)

    def netwarden_add(self, srcAddr, srcPort, dstAddr, dstPort):
        print "adding a conn entry"
        conn_tab_ms = p4_pd.conn_tab_match_spec_t(srcAddr, srcPort, dstAddr, dstPort)
        conn_tab_ms2 = p4_pd.conn_tab_match_spec_t(dstAddr, dstPort, srcAddr, srcPort)

        concat1 = str(srcAddr)+str(srcPort)+str(dstAddr)+str(dstPort)
        concat2 = str(dstAddr)+str(dstPort)+str(srcAddr)+str(srcPort)
        for i in range(len(self.conn_entries)):
            if self.conn_entries[i] == concat1 or self.conn_entries[i] == concat2:
                print "repeat conn entries, skip"
                return
        self.conn_entries.append(concat1)
        self.conn_entries.append(concat2)

        # find a free idx
        if len(self.free_idxs) == 0:
            print "Error, no indexes available (either conn_table is full or there is a bug)"
            return

        idx = self.free_idxs.pop()
        try:
            conn_tab_as = p4_pd.set_conn_idx_action_spec_t(idx)
            # print "The assigned index is: "+str(idx)
            conn_tab_es = p4_pd.conn_tab_table_add_with_set_conn_idx(conn_tab_ms, conn_tab_as)
            conn_tab_es = p4_pd.conn_tab_table_add_with_set_conn_idx(conn_tab_ms2, conn_tab_as)

        except Exception as e:
            print "Exception adding conn entry: ", e
            return

        print "Finish adding a conn entry"

    def recycle_idx(self, idx):
        self.free_idxs.append(idx)


    def do_kstest(self, ipds):
        d, p = ks_2samp(self.train_data, ipds)
        # print (d, p)

        if p < 0.01:
           return True
        else:
           return False

    def add_entry_cpu(self, srcAddr, srcPort, dstAddr, dstPort):
        # print "adding a cpu entry"
        concat1 = str(srcAddr)+str(srcPort)+str(dstAddr)+str(dstPort)
        concat2 = str(dstAddr)+str(dstPort)+str(srcAddr)+str(srcPort)
        for i in range(len(self.fpkt_entries)):
            if self.fpkt_entries[i] == concat1 or self.fpkt_entries[i] == concat2:
                # print "repeat fpkt entries, skip"
                return
        self.fpkt_entries.append(concat1)
        self.fpkt_entries.append(concat2)

        timing_cpu_tab_ms1 = p4_pd.nhop_cp_tab_match_spec_t(srcAddr, srcPort, dstAddr, dstPort)
        timing_cpu_tab_ms2 = p4_pd.nhop_cp_tab_match_spec_t(dstAddr, dstPort, srcAddr, srcPort)

        try:
            timing_cpu_tab_es = p4_pd.nhop_cp_tab_table_add_with_send_to_cp(timing_cpu_tab_ms1)
            timing_cpu_tab_es = p4_pd.nhop_cp_tab_table_add_with_send_to_cp(timing_cpu_tab_ms2)
        except Exception as e:
            print "Exception adding timing cpu entry: ", e
            return
