#ifndef __CHECKSUM_P4__
#define __CHECKSUM_P4__

#include "headers.p4" // Ensure this is included to access headers_t

control VerifyChecksumImpl(inout headers_t hdr, inout meta_t m) { apply { } }
control ComputeChecksumImpl(inout headers_t hdr, inout meta_t m) { apply { } }

#endif /* __CHECKSUM_P4__ */
