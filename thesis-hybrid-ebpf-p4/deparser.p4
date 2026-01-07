control DeparserImpl(packet_out pkt, in ethernet_t ethernet, in vlan_tag_t vlan_tag, in ipv4_t ipv4, in tcp_t tcp)
{
    apply {
        pkt.emit(ethernet);
        if (vlan_tag.isValid()) pkt.emit(vlan_tag);
        pkt.emit(ipv4);
        if (tcp.isValid()) pkt.emit(tcp);
    }
}
