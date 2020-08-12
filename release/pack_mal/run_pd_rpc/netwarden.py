__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'

import collections

CONN_TB_SIZE = 100000

class netwarden():
    def __init__(self):
        self.all_ports  = []
        self.free_idxs = []
        self.conn_entries = [] # installed conn entries

        for pipe in range(0, 3):
            for port in range(0, 63):
                self.all_ports.append(to_devport(pipe, port))
            if pipe % 2 == 0:
                self.all_ports.append(to_devport(pipe, 64))


    def setup(self):
        clear_all()

        print "Setting up indexes"
        for i in range(CONN_TB_SIZE):
            self.free_idxs.append(i)

        p4_pd.check_pack_tab_table_add_with_skip(p4_pd.check_pack_tab_match_spec_t(0))



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
            print "The assigned index is: "+str(idx)
            conn_tab_es = p4_pd.conn_tab_table_add_with_set_conn_idx(conn_tab_ms, conn_tab_as)
            conn_tab_es = p4_pd.conn_tab_table_add_with_set_conn_idx(conn_tab_ms2, conn_tab_as)

        except Exception as e:
            print "Exception adding conn entry: ", e
            return

    def recycle_idx(self, idx):
        self.free_idxs.append(idx)
