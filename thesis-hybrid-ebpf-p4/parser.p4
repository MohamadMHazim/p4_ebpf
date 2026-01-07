parser ParserImpl(packet_in pkt,
                  out ethernet_t ethernet,
                  out vlan_tag_t vlan_tag,
                  out ipv4_t ipv4,
                  out tcp_t tcp)
{
    state start {
        pkt.extract(ethernet);
        transition select(ethernet.eth_type) {
            0x0800: parse_ipv4;      // Ethernet + IPv4
            0x8100: parse_vlan_tag;  // VLAN tag
            default: accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(vlan_tag);
        transition select(vlan_tag.eth_type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(ipv4);
        transition select(ipv4.protocol) {
            0x06: parse_tcp;  // TCP
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(tcp);
        transition accept;
    }
}
