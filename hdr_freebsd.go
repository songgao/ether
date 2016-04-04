package ether

import "golang.org/x/sys/unix"

/*
 * From bpf.h:
 *
 *   struct bpf_hdr {
 *      struct timeval   bh_tstamp;
 *  	uint32_t         bh_caplen;
 *  	uint32_t         bh_datalen;
 *  	u_short          bh_hdrlen;
 *   };
 *
 * Note: FreeBSD may deprecate bpf_hdr in favor of bpf_xhdr in the future
 *
 */
type bpfHdr struct {
	_       unix.Timeval // 8 or 16 bytes depending on arch
	caplen  uint32
	datalen uint32
	hdrlen  uint16
}
