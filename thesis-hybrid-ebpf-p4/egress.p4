control EgressImpl(inout ethernet_t ethernet,
                   inout vlan_tag_t vlan_tag,
                   inout ipv4_t ipv4,
                   inout tcp_t tcp)
{
    action drop_packet() {
        // Dropping logic for invalid packets
    }

    table drop_on_error {
        key = {
            ipv4.srcAddr : exact;
        }
        actions = { drop_packet; }
        size = 1024;  // Adjust size as needed
    }

    apply {
        drop_on_error.apply();
    }
}
