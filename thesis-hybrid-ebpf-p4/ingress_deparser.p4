    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
apply {
    pkt.emit(hdr.ethernet);
    pkt.emit(hdr.ipv4);
    pkt.emit(hdr.tcp);
    pkt.emit(hdr.udp);
}

}