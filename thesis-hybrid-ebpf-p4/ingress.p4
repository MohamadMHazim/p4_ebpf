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

    /*********************** Registers ************************/
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_pkts;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_bytes;

    // Packet length stats (IPv4 totalLen)
    Register<bit<16>, bit<16>>(FLOW_BUCKETS) reg_min_len;
    Register<bit<16>, bit<16>>(FLOW_BUCKETS) reg_max_len;

    // IAT stats
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_last_ts;   // last timestamp
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_iat_sum;   // sum of deltas
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_iat_cnt;   // number of deltas
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_iat_min;   // min delta (auto-init)
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_iat_max;   // max delta (auto-init)

    // TCP flags
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
        void apply(inout bit<32> v) { v = v + (bit<32>) hdr.ipv4.totalLen; }
    };

    // min_len = min(min_len, L) (0 means unset)
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_min_len) min_len_update = {
        void apply(inout bit<16> v) {
            bit<16> L = hdr.ipv4.totalLen;
            if (v == 0 || L < v) { v = L; }
        }
    };

    // max_len = max(max_len, L)
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_max_len) max_len_update = {
        void apply(inout bit<16> v) {
            bit<16> L = hdr.ipv4.totalLen;
            if (L > v) { v = L; }
        }
    };

    // last_ts: read old and write new in same action (TNA: execute() returns old)
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_last_ts) last_ts_rw = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            v   = (bit<32>) ig_intr_md.ingress_mac_tstamp;
        }
    };

    // iat_sum += cur_iat
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_iat_sum) iat_sum_add = {
        void apply(inout bit<32> v) {
            if (meta.iat_valid == 1w1) { v = v + meta.cur_iat; }
        }
    };

    // iat_cnt++ but also return old count (so we can init min/max outside)
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_iat_cnt) iat_cnt_rw = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            if (meta.iat_valid == 1w1) { v = v + 32w1; }
        }
    };

    // iat_min = cur_iat (init)
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_iat_min) iat_min_set = {
        void apply(inout bit<32> v) { v = meta.cur_iat; }
    };

    // iat_max = cur_iat (init)
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_iat_max) iat_max_set = {
        void apply(inout bit<32> v) { v = meta.cur_iat; }
    };

    // iat_min = min(iat_min, cur_iat)  (2 comparisons only)
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_iat_min) iat_min_update = {
        void apply(inout bit<32> v) {
            if (meta.iat_valid == 1w1) {
                if (meta.cur_iat < v) { v = meta.cur_iat; }
            }
        }
    };

    // iat_max = max(iat_max, cur_iat)
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_iat_max) iat_max_update = {
        void apply(inout bit<32> v) {
            if (meta.iat_valid == 1w1) {
                if (meta.cur_iat > v) { v = meta.cur_iat; }
            }
        }
    };

    // TCP flag counters
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_syn) syn_update = {
        void apply(inout bit<32> v) { if (meta.f_syn == 1w1) v = v + 32w1; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ack) ack_update = {
        void apply(inout bit<32> v) { if (meta.f_ack == 1w1) v = v + 32w1; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_fin) fin_update = {
        void apply(inout bit<32> v) { if (meta.f_fin == 1w1) v = v + 32w1; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_rst) rst_update = {
        void apply(inout bit<32> v) { if (meta.f_rst == 1w1) v = v + 32w1; }
    };

    /*********************** Forwarding ************************/
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
        // init flags + iat state
        meta.f_syn = 1w0; meta.f_ack = 1w0; meta.f_fin = 1w0; meta.f_rst = 1w0;
        meta.iat_valid = 1w0;
        meta.cur_iat   = 32w0;

        if (hdr.ipv4.isValid()) {
            bit<16> idx = crc16_hasher.get({
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                meta.l4_sport,
                meta.l4_dport,
                hdr.ipv4.protocol
            });
            meta.flow_index = idx;

            // basic stats
            pkts_add.execute(idx);
            bytes_add.execute(idx);
            min_len_update.execute(idx);
            max_len_update.execute(idx);

            // IAT: get old timestamp and update last_ts
            bit<32> now_ts = (bit<32>) ig_intr_md.ingress_mac_tstamp;
            bit<32> old_ts = last_ts_rw.execute(idx);

            if (old_ts != 0) {
                meta.iat_valid = 1w1;
                meta.cur_iat   = now_ts - old_ts;

                // update sum first (uses meta.cur_iat)
                iat_sum_add.execute(idx);

                // increment cnt and fetch old count for init logic
                bit<32> old_cnt = iat_cnt_rw.execute(idx);

                // first valid delta => init min/max to this delta
                if (old_cnt == 0) {
                    iat_min_set.execute(idx);
                    iat_max_set.execute(idx);
                } else {
                    iat_min_update.execute(idx);
                    iat_max_update.execute(idx);
                }
            }

            // TCP flags
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