const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;

header ethernet_t {
    bit<48> dst;
    bit<48> src;
    bit<16> eth_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

struct my_headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

struct my_ingress_metadata_t {
    bit<16> flow_index;   // hash index (for debug if you want)
    bit<16> l4_sport;
    bit<16> l4_dport;

    bit<1>  is_tcp;
    bit<1>  is_udp;

    // TCP flags (set in ingress before reg updates)
    bit<1>  f_syn;
    bit<1>  f_ack;
    bit<1>  f_fin;
    bit<1>  f_rst;

    // IAT helpers (used for reg_iat_min/max/sum logic)
    bit<1>  iat_valid;
    bit<32> cur_iat;
}

struct my_egress_headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

struct my_egress_metadata_t {
}