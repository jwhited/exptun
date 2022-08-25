package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"net/netip"
	"os"
	"os/exec"
)

var (
	flagTunName    = flag.String("tun-name", "exptun", "name of TUN device")
	flagTunAddr    = flag.String("tun-addr", "172.16.255.1/32", "address of TUN device")
	flagTunRoute   = flag.String("tun-route", "172.16.255.2/32", "route towards TUN device")
	flagTunTSOMode = flag.Int("tun-tso-mode", 0, "0 (off); 1 (echo); 2 (split)")
)

const (
	tunPath = "/dev/net/tun"
)

func checksum(b []byte, initial uint32) uint16 {
	sum := initial

	for i := 0; i < len(b); i += 2 {
		if i == len(b)-1 {
			sum += uint32(b[i]) << 8
		} else {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}

	for {
		if sum>>16 == 0 {
			break
		}
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(^sum)
}

const (
	virtioNetHdrLen = 10
)

const (
	// virtioNetHdr Flags
	VIRTIO_NET_HDR_F_NEEDS_CSUM = 0x1

	// virtioNetHdr GSOType
	VIRTIO_NET_HDR_GSO_NONE  = 0x0
	VIRTIO_NET_HDR_GSO_TCPV4 = 0x1
)

type virtioNetHdr struct {
	Flags      uint8
	GSOType    uint8
	HdrLen     uint16
	GSOSize    uint16
	CSumStart  uint16
	CSumOffset uint16
}

type packetHandler struct {
	reader            *bytes.Reader
	tunAddr, tunRoute netip.Prefix
	mode              tsoMode
}

func pseudoHeaderMinusLenFromPacket(b []byte) []byte {
	ret := make([]byte, 10)
	copy(ret[:4], b[12:16])
	copy(ret[4:], b[16:20])
	ret[9] = unix.IPPROTO_TCP
	return ret
}

func tcpChecksum(b []byte, pseudoHeaderMinusLen []byte) uint16 {
	b[16], b[17] = 0, 0 // clear
	tcpCsumData := make([]byte, len(pseudoHeaderMinusLen)+2+len(b[20:]))
	copy(tcpCsumData, pseudoHeaderMinusLen)
	binary.BigEndian.PutUint16(tcpCsumData[10:], uint16(len(b[20:])))
	copy(tcpCsumData[12:], b[20:])
	tcpCsum := checksum(tcpCsumData, 0)
	return tcpCsum
}

// handle handles the provided packet 'in'. If handle results in packets that
// should be written to the TUN device it will return true, with the packets
// written to out, and their sizes in the returned slice of ints.
func (p *packetHandler) handle(in []byte, out [][]byte) ([]int, bool) {
	p.reader.Reset(in)
	var vnetHdr virtioNetHdr
	startAtIPH := in

	if p.mode > tsoModeOff {
		if len(in) < virtioNetHdrLen {
			return nil, false
		}
		err := binary.Read(p.reader, binary.LittleEndian, &vnetHdr)
		if err != nil {
			return nil, false
		}
		if vnetHdr.GSOType != VIRTIO_NET_HDR_GSO_NONE && vnetHdr.GSOType != VIRTIO_NET_HDR_GSO_TCPV4 {
			return nil, false
		}
		startAtIPH = in[virtioNetHdrLen:]
	}

	// NAT packets from address behind TUN device
	if len(startAtIPH) < 40 {
		return nil, false
	}
	if startAtIPH[0]>>4 != 4 { // only IPv4 for now
		return nil, false
	}
	if startAtIPH[0]&0x0F != 5 { // ignore ip options for now
		return nil, false
	}
	if startAtIPH[9] != unix.IPPROTO_TCP { // ignore non-tcp
		return nil, false
	}
	srcAddr, _ := netip.AddrFromSlice(startAtIPH[12:16])
	dstAddr, _ := netip.AddrFromSlice(startAtIPH[16:20])
	if srcAddr.Compare(p.tunAddr.Addr()) != 0 {
		return nil, false
	}
	if !p.tunRoute.Contains(dstAddr) {
		return nil, false
	}
	// swap src/dst addrs
	copy(startAtIPH[12:16], dstAddr.AsSlice())
	copy(startAtIPH[16:20], srcAddr.AsSlice())

	if p.mode < tsoModeSplit || vnetHdr.GSOType == VIRTIO_NET_HDR_GSO_NONE {
		copy(out[0], in)
		return []int{len(in)}, true
	}

	startAtIPH[10], startAtIPH[11] = 0, 0 // clear IPv4 checksum field

	// psuedoheaderMinusLen for tcp checksum. We don't want len (yet) as it may
	// vary for final segment.
	psuedoHeaderMinusLen := pseudoHeaderMinusLenFromPacket(startAtIPH)

	tcpCsumAt := vnetHdr.CSumStart + vnetHdr.CSumOffset
	in[tcpCsumAt], in[tcpCsumAt+1] = 0, 0 // clear TCP checksum field before splitting

	// TODO: split segments
	_ = psuedoHeaderMinusLen
	nextSegmentAt := virtioNetHdrLen + int(vnetHdr.HdrLen)
	sizes := make([]int, 0, len(out))
	for i := 0; nextSegmentAt < len(in); i++ {
		fmt.Printf("len(in): %d nextSegmentAt: %d\n", len(in), nextSegmentAt)
		copy(out[i], make([]byte, virtioNetHdrLen))                             // empty virtioNetHdr
		copy(out[i][virtioNetHdrLen:], in[:20])                                 // ipv4 header
		copy(out[i][virtioNetHdrLen+20:], in[vnetHdr.CSumStart:vnetHdr.HdrLen]) // tcp header

		// TODO: set IPv4 header len
		// TODO: set TCP sequence number
		// TODO: set TCP len
		// TODO: TCP checksum

		// payload varies
		copy(out[i][vnetHdr.HdrLen:], in[nextSegmentAt:])                                    // payload
		sizes = append(sizes, virtioNetHdrLen+20+int(vnetHdr.HdrLen)-int(vnetHdr.CSumStart)) // virtioNetHdr + iph len + tcph len + payload len
		nextSegmentAt += int(vnetHdr.GSOSize)
	}
	return sizes, true
}

func run(prog string, args ...string) error {
	cmd := exec.Command(prog, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error running %v: %v", cmd, err)
	}
	return nil
}

type tsoMode int

const (
	tsoModeOff   tsoMode = 0
	tsoModeEcho  tsoMode = 1
	tsoModeSplit tsoMode = 2
)

func (t tsoMode) valid() bool {
	return t >= 0 && t <= 2
}

func (t tsoMode) String() string {
	switch t {
	case tsoModeOff:
		return "off"
	case tsoModeEcho:
		return "echo"
	case tsoModeSplit:
		return "split"
	default:
		return "unknown"
	}
}

func main() {
	flag.Parse()

	tunAddr, err := netip.ParsePrefix(*flagTunAddr)
	if err != nil {
		log.Fatalf("error parsing tun addr (%s): %v", *flagTunAddr, err)
	}
	tunRoute, err := netip.ParsePrefix(*flagTunRoute)
	if err != nil {
		log.Fatalf("error parsing tun route (%s): %v", *flagTunRoute, err)
	}

	mode := tsoMode(*flagTunTSOMode)
	if !mode.valid() {
		log.Fatalf("invalid tso mode: %d", *flagTunTSOMode)
	}

	fd, err := setupDevice(*flagTunName, mode != tsoModeOff)
	if err != nil {
		log.Fatalf("error setting up TUN device: %v", err)
	}
	log.Printf("TUN device %s created\n", *flagTunName)

	f := os.NewFile(uintptr(fd), tunPath)
	if f == nil {
		log.Fatal("failed to create os.File from fd")
	}

	if err = run("ip", "link", "set", "dev", *flagTunName, "up"); err != nil {
		log.Fatalf("error bringing TUN up: %v", err)
	}

	if err = run("ip", "addr", "add", tunAddr.String(), "dev", *flagTunName); err != nil {
		log.Fatalf("error adding addr to TUN: %v", err)
	}

	if err = run("ip", "route", "add", tunRoute.String(), "dev", *flagTunName); err != nil {
		log.Fatalf("error adding route to TUN: %v", err)
	}

	const (
		mtu            = 1500
		maxSegmentSize = 65535
		maxSegments    = maxSegmentSize/mtu + 1
	)
	in := make([]byte, maxSegmentSize)
	out := make([][]byte, maxSegments)
	for i := 0; i < len(out); i++ {
		out[i] = make([]byte, maxSegmentSize)
	}
	handler := &packetHandler{
		reader:   bytes.NewReader(nil),
		tunAddr:  tunAddr,
		tunRoute: tunRoute,
		mode:     mode,
	}
	for {
		n, err := f.Read(in)
		if err != nil {
			log.Fatalf("error reading from TUN: %v", err)
		}
		sizes, ok := handler.handle(in[:n], out)
		if !ok {
			continue
		}
		for i := 0; i < len(sizes); i++ {
			_, err = f.Write(out[i][:sizes[i]])
			if err != nil {
				log.Fatalf("error writing to TUN: %v", err)
			}
		}

	}
}
