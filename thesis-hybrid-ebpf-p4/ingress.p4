const bit<32> FLOW_BUCKETS = 65536;

control Ingress(
    inout my_headers_t hdr,
    inout my_ingress_metadata_t meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_hasher;

    /************** DEBUG: store computed hash index **************/
Register<bit<16>, bit<1>>(1) reg_dbg_idx;

/* write computed index into reg_dbg_idx[0] */
RegisterAction<bit<16>, bit<1>, bit<16>>(reg_dbg_idx) dbg_idx_set = {
    void apply(inout bit<16> v, out bit<16> rv) {
        v  = meta.flow_index;  // store current flow_index
        rv = v;
    }
};

    /*********************** Registers ************************/
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_pkts;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_bytes;

    // Register<bit<16>, bit<16>>(FLOW_BUCKETS) reg_min_len;
    // Register<bit<16>, bit<16>>(FLOW_BUCKETS) reg_max_len;

    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_last_ts;
    // Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_iat_min;
    // Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_iat_max;

    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_syn;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_ack;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_fin;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_rst;

    /*********************** RegisterActions ************************/

    // packets++
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_pkts) pkts_add = {
        void apply(inout bit<32> v) { v = v + 32w1; }
    };

    // bytes += ipv4.totalLen
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_bytes) bytes_add = {
        void apply(inout bit<32> v) {
            bit<16> L = hdr.ipv4.totalLen;
            v = v + (bit<32>) L;
        }
    };

    // min_len = min(min_len, L), where 0 means uninitialized
    // RegisterAction<bit<16>, bit<16>, bit<16>>(reg_min_len) min_update = {
    //     void apply(inout bit<16> v) {
    //         bit<16> L = hdr.ipv4.totalLen;
    //         if (v == 0 || L < v) { v = L; }
    //     }
    // };

    // // max_len = max(max_len, L)
    // RegisterAction<bit<16>, bit<16>, bit<16>>(reg_max_len) max_update = {
    //     void apply(inout bit<16> v) {
    //         bit<16> L = hdr.ipv4.totalLen;
    //         if (L > v) { v = L; }
    //     }
    // };

    // last_ts update (store now)
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_last_ts) last_ts_set = {
        void apply(inout bit<32> v) {
            // choose ONE timestamp source; global_tstamp is also available
            v = (bit<32>) ig_intr_md.ingress_mac_tstamp;
        }
    };

    // // iat_min update (needs current iat in metadata)
    // RegisterAction<bit<32>, bit<16>, bit<32>>(reg_iat_min) iat_min_update = {
    //     void apply(inout bit<32> v) {
    //         if (meta.has_iat == 1w1) {
    //             if (v == 0 || meta.cur_iat < v) { v = meta.cur_iat; }
    //         }
    //     }
    // };

    // // iat_max update
    // RegisterAction<bit<32>, bit<16>, bit<32>>(reg_iat_max) iat_max_update = {
    //     void apply(inout bit<32> v) {
    //         if (meta.has_iat == 1w1) {
    //             if (meta.cur_iat > v) { v = meta.cur_iat; }
    //         }
    //     }
    // };

    // TCP flags counters (bit<9>)
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_syn) syn_update = {
        void apply(inout bit<32> v) {
            if (meta.f_syn == 1w1) { v = v + 32w1; }
        }
    };

    /* ACK++ */
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ack) ack_update = {
        void apply(inout bit<32> v) {
            if (meta.f_ack == 1w1) { v = v + 32w1; }
        }
    };

    /* FIN++ */
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_fin) fin_update = {
        void apply(inout bit<32> v) {
            if (meta.f_fin == 1w1) { v = v + 32w1; }
        }
    };

    /* RST++ */
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_rst) rst_update = {
        void apply(inout bit<32> v) {
            if (meta.f_rst == 1w1) { v = v + 32w1; }
        }
    };

    action send_using_port(PortId_t port) {
    ig_tm_md.ucast_egress_port = port;
    ig_tm_md.bypass_egress     = 0;
}

    action drop() {
        ig_dprsr_md.drop_ctl       = 3w1;
        ig_tm_md.bypass_egress     = 1w1;
    }

    table forwarding {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { send_using_port; drop; }
        const default_action = drop();
        size = 256;
    }
    /*********************** Apply ************************/
apply {
    if (hdr.ipv4.isValid()) {

        bit<16> idx = crc16_hasher.get({
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            meta.l4_sport,
            meta.l4_dport,
            hdr.ipv4.protocol
        });

        meta.flow_index = idx;

        // ✅ store computed index into reg_dbg_idx[0]
        dbg_idx_set.execute(0);

        // real counters at computed idx
        pkts_add.execute(idx);
        bytes_add.execute(idx);

        // (optional) TCP flags
        meta.f_syn = 1w0; meta.f_ack = 1w0; meta.f_fin = 1w0; meta.f_rst = 1w0;

        if (hdr.tcp.isValid()) {
            bit<9> f = hdr.tcp.flags;
            if ((f & 9w0x002) != 0) { meta.f_syn = 1w1; }
            if ((f & 9w0x010) != 0) { meta.f_ack = 1w1; }
            if ((f & 9w0x001) != 0) { meta.f_fin = 1w1; }
            if ((f & 9w0x004) != 0) { meta.f_rst = 1w1; }

            syn_update.execute(idx);
            ack_update.execute(idx);
            fin_update.execute(idx);
            rst_update.execute(idx);
        }
    }

    forwarding.apply();
}
}