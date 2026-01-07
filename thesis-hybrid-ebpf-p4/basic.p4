#include <core.p4>
#include <tna.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_TCP   = 6;
const bit<16> TCP_PORT_HTTPS = 443;
const bit<32> FLOW_BUCKETS   = 65536;

#include "headers.p4"
#include "parser.p4"
#include "checksum.p4"
#include "ingress.p4"
#include "egress.p4"
#include "deparser.p4"

TNA_Main(ParserImpl(), VerifyChecksumImpl(), IngressImpl(),
         EgressImpl(), ComputeChecksumImpl(), DeparserImpl()) main;
