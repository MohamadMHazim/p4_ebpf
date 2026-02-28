parser IngressParser(
    packet_in pkt,
    out my_headers_t hdr,
    out my_ingress_metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md
) {
state start {
    pkt.extract(ig_intr_md);
    pkt.advance(PORT_METADATA_SIZE);

    meta.flow_index = 16w0;
    meta.l4_sport   = 16w0;
    meta.l4_dport   = 16w0;
    meta.is_tcp     = 1w0;
    meta.is_udp     = 1w0;

    transition parse_ethernet;
}

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.eth_type) {
        ETHERTYPE_IPV4: parse_ipv4;
        default: accept;
    }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.is_tcp  = 1w1;
        meta.is_udp  = 1w0;
        meta.l4_sport = hdr.tcp.srcPort;
        meta.l4_dport = hdr.tcp.dstPort;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.is_tcp  = 1w0;
        meta.is_udp  = 1w1;
        meta.l4_sport = hdr.udp.src_port;
        meta.l4_dport = hdr.udp.dst_port;
        transition accept;
    }
}