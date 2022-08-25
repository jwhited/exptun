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

func checksum(b []byte) uint16 {
	var sum uint32

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
	tcpCsum := checksum(tcpCsumData)
	return tcpCsum
}

// handle handles the provided packet 'in'. If handle results in packets that
// should be written to the TUN device it will return true, with the packets
// written to out, and their sizes in the returned slice of ints.
func (p *packetHandler) handle(in []byte, out [][]byte) ([]int, bool) {
	p.reader.Reset(in)
	var vnetHdr virtioNetHdr
	inStartAtIPH := in

	if p.mode > tsoModeOff {
		if len(in) < virtioNetHdrLen {
			return nil, false
		}
		err := binary.Read(p.reader, binary.LittleEndian, &vnetHdr)
		if err != nil {
			return nil, false
		}
		if vnetHdr.GSOType&VIRTIO_NET_HDR_GSO_NONE|VIRTIO_NET_HDR_GSO_TCPV4 == 0 {
			return nil, false
		}
		inStartAtIPH = in[virtioNetHdrLen:]
	}

	// NAT packets from address behind TUN device
	if len(inStartAtIPH) < 40 {
		return nil, false
	}
	if inStartAtIPH[0]>>4 != 4 { // only IPv4 for now
		return nil, false
	}
	if inStartAtIPH[0]&0x0F != 5 { // ignore ip options for now
		return nil, false
	}
	if inStartAtIPH[9] != unix.IPPROTO_TCP { // ignore non-tcp
		return nil, false
	}
	srcAddr, _ := netip.AddrFromSlice(inStartAtIPH[12:16])
	dstAddr, _ := netip.AddrFromSlice(inStartAtIPH[16:20])
	if srcAddr.Compare(p.tunAddr.Addr()) != 0 {
		return nil, false
	}
	if !p.tunRoute.Contains(dstAddr) {
		return nil, false
	}
	// swap src/dst addrs
	copy(inStartAtIPH[12:16], dstAddr.AsSlice())
	copy(inStartAtIPH[16:20], srcAddr.AsSlice())

	if p.mode < tsoModeSplit || vnetHdr.GSOType == VIRTIO_NET_HDR_GSO_NONE {
		copy(out[0], in)
		return []int{len(in)}, true
	}

	inStartAtIPH[10], inStartAtIPH[11] = 0, 0 // clear IPv4 checksum field

	// psuedoheaderMinusLen for tcp checksum. We don't want len (yet) as it may
	// vary for final segment.
	psuedoHeaderMinusLen := pseudoHeaderMinusLenFromPacket(inStartAtIPH)

	tcpCsumAt := vnetHdr.CSumStart + vnetHdr.CSumOffset
	in[tcpCsumAt], in[tcpCsumAt+1] = 0, 0 // clear TCP checksum field before splitting

	// TODO: split segments
	_ = psuedoHeaderMinusLen
	nextSegmentAt := virtioNetHdrLen + int(vnetHdr.HdrLen)
	sizes := make([]int, 0, len(out))
	for i := 0; nextSegmentAt < len(in); i++ {
		end := nextSegmentAt + int(vnetHdr.GSOSize)
		if end > len(in) {
			end = len(in)
		}

		// empty virtioNetHdr
		for j := 0; j < virtioNetHdrLen; j++ {
			out[i][j] = 0
		}

		// IPv4 header
		startAtIPH := virtioNetHdrLen
		copy(out[i][startAtIPH:], inStartAtIPH[:20])
		totalLen := int(vnetHdr.HdrLen) + (end - nextSegmentAt)
		binary.BigEndian.PutUint16(out[i][startAtIPH+2:], uint16(totalLen))
		ipv4CSum := checksum(out[i][startAtIPH : startAtIPH+20])
		binary.BigEndian.PutUint16(out[i][startAtIPH+10:], ipv4CSum)

		// TCP header
		startAtTCP := virtioNetHdrLen + vnetHdr.CSumStart
		copy(out[i][startAtTCP:], in[startAtTCP:virtioNetHdrLen+vnetHdr.HdrLen])
		// TODO: set TCP sequence number
		// TODO: TCP checksum
		fmt.Printf("len(in): %d vnetHdr: %+v nextSegmentAt: %d end: %d totalLen: %d\n", len(in), vnetHdr, nextSegmentAt, end, totalLen)

		// payload
		copy(out[i][virtioNetHdrLen+vnetHdr.HdrLen:], in[nextSegmentAt:end])
		sizes = append(sizes, totalLen)
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
		if len(sizes) > 1 {
			log.Printf("in minus virtio: %x\n", in[virtioNetHdrLen:n])
			for i := 0; i < len(sizes); i++ {
				log.Printf("out[%d] minus virtio: %x\n", i, out[i][virtioNetHdrLen:sizes[i]])
			}
		}
		for i := 0; i < len(sizes); i++ {
			_, err = f.Write(out[i][:sizes[i]])
			if err != nil {
				log.Fatalf("error writing to TUN: %v", err)
			}
		}

	}
}
