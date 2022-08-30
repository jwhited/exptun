package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"os/exec"
)

var (
	flagTunName    = flag.String("tun-name", "exptun", "name of TUN device")
	flagTunAddr    = flag.String("tun-addr", "172.16.255.1/32", "address of TUN device")
	flagTunRoute   = flag.String("tun-route", "172.16.255.2/32", "route towards TUN device")
	flagTunTSOMode = flag.Int("tun-tso-mode", 0, "0 (off); 1 (echo); 2 (split); 3 (split no csum)")
	flagPprofAddr  = flag.String("pprof-addr", "", "pprof http server listen addr")
)

const (
	tunPath = "/dev/net/tun"
)

func checksum(b []byte) uint16 {
	var ac uint64
	i := 0
	n := len(b)
	for n >= 4 {
		ac += uint64(binary.BigEndian.Uint32(b[i : i+4]))
		n -= 4
		i += 4
	}
	for n >= 2 {
		ac += uint64(binary.BigEndian.Uint16(b[i : i+2]))
		n -= 2
		i += 2
	}
	if n == 1 {
		ac += uint64(b[i]) << 8
	}
	for (ac >> 16) > 0 {
		ac = (ac >> 16) + (ac & 0xffff)
	}
	return uint16(^ac)
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

func (v *virtioNetHdr) encode(bo binary.ByteOrder, b []byte) error {
	if len(b) < virtioNetHdrLen {
		return errors.New("too short")
	}
	b[0] = v.Flags
	b[1] = v.GSOType
	bo.PutUint16(b[2:], v.HdrLen)
	bo.PutUint16(b[2:], v.GSOSize)
	bo.PutUint16(b[2:], v.CSumStart)
	bo.PutUint16(b[2:], v.CSumOffset)
	return nil
}

func (v *virtioNetHdr) decode(bo binary.ByteOrder, b []byte) error {
	if len(b) < virtioNetHdrLen {
		return errors.New("too shor")
	}
	v.Flags = b[0]
	v.GSOType = b[1]
	v.HdrLen = bo.Uint16(b[2:])
	v.GSOSize = bo.Uint16(b[4:])
	v.CSumStart = bo.Uint16(b[6:])
	v.CSumOffset = bo.Uint16(b[8:])
	return nil
}

type packetHandler struct {
	tunAddr, tunRoute netip.Prefix
	mode              tsoMode
	buff              [65535]byte
	psuedoHeader      [12]byte
	sizes             []int
}

// handle handles the provided packet 'in'. If handle results in packets that
// should be written to the TUN device it will return true, with the packets
// written to out, and their sizes in the returned slice of ints.
func (p *packetHandler) handle(in []byte, out [][]byte) ([]int, bool) {
	var vnetHdr virtioNetHdr
	var ipHLen int
	inStartAtIPH := in

	if p.mode > tsoModeOff {
		err := vnetHdr.decode(binary.LittleEndian, in)
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
	ipHLen = 20
	if inStartAtIPH[9] != unix.IPPROTO_TCP { // ignore non-tcp
		return nil, false
	}
	copy(p.buff[:], inStartAtIPH[12:16])
	copy(inStartAtIPH[12:16], inStartAtIPH[16:20])
	copy(inStartAtIPH[16:20], p.buff[:4])

	if p.mode < tsoModeSplit || vnetHdr.GSOType == VIRTIO_NET_HDR_GSO_NONE {
		copy(out[0], in)
		p.sizes[0] = len(in)
		return p.sizes[:1], true
	}

	inStartAtIPH[10], inStartAtIPH[11] = 0, 0 // clear IPv4 checksum field

	if p.mode == tsoModeSplit {
		copy(p.psuedoHeader[:], inStartAtIPH[12:16])
		copy(p.psuedoHeader[4:], inStartAtIPH[16:20])
		p.psuedoHeader[9] = unix.IPPROTO_TCP
		p.psuedoHeader[10], p.psuedoHeader[11] = 0, 0
	}

	tcpCsumAt := virtioNetHdrLen + vnetHdr.CSumStart + vnetHdr.CSumOffset
	in[tcpCsumAt], in[tcpCsumAt+1] = 0, 0 // clear TCP checksum field before splitting
	firstTCPSeq := binary.BigEndian.Uint32(in[virtioNetHdrLen+vnetHdr.CSumStart+4:])

	nextSegmentAt := virtioNetHdrLen + int(vnetHdr.HdrLen)
	numSegments := 0
	for i := 0; nextSegmentAt < len(in); i++ {
		end := nextSegmentAt + int(vnetHdr.GSOSize)
		if end > len(in) {
			end = len(in)
		}

		// empty virtioNetHdr
		outVNetHdr := virtioNetHdr{}
		if p.mode == tsoModeSplitNoCsum {
			outVNetHdr.Flags = VIRTIO_NET_HDR_F_NEEDS_CSUM
			outVNetHdr.CSumStart = 20
			outVNetHdr.CSumOffset = 16
		}
		err := outVNetHdr.encode(binary.LittleEndian, out[i])
		if err != nil {
			return nil, false
		}

		// IPv4 header
		startAtIPH := virtioNetHdrLen
		copy(out[i][startAtIPH:], inStartAtIPH[:20])
		totalLen := int(vnetHdr.HdrLen) + (end - nextSegmentAt)
		binary.BigEndian.PutUint16(out[i][startAtIPH+2:], uint16(totalLen))
		// When splitting we always want to compute a valid iph checksum. We
		// can't offload this back to the kernel.
		ipv4CSum := checksum(out[i][startAtIPH : startAtIPH+20])
		binary.BigEndian.PutUint16(out[i][startAtIPH+10:], ipv4CSum)

		// TCP header
		startAtTCP := virtioNetHdrLen + vnetHdr.CSumStart
		copy(out[i][startAtTCP:], in[startAtTCP:virtioNetHdrLen+vnetHdr.HdrLen])
		if i > 0 {
			// TODO: overflow and stuff
			tcpSeq := int(firstTCPSeq) + int(vnetHdr.GSOSize)*i
			binary.BigEndian.PutUint32(out[i][startAtTCP+4:], uint32(tcpSeq))
		}

		// payload
		copy(out[i][virtioNetHdrLen+vnetHdr.HdrLen:], in[nextSegmentAt:end])

		// TCP checksum
		if p.mode == tsoModeSplit {
			tcpHLen := int(vnetHdr.HdrLen) - ipHLen
			tcpLenForPseudo := tcpHLen + (end - nextSegmentAt)
			binary.BigEndian.PutUint16(p.psuedoHeader[10:], uint16(tcpLenForPseudo))
			copy(p.buff[:], p.psuedoHeader[:])
			copy(p.buff[len(p.psuedoHeader):], out[i][startAtTCP:])
			tcpCSum := checksum(p.buff[:len(p.psuedoHeader)+len(out[i][startAtTCP:])])
			binary.BigEndian.PutUint16(out[i][startAtTCP+16:], tcpCSum)
		}

		p.sizes[i] = virtioNetHdrLen + totalLen
		numSegments++
		nextSegmentAt += int(vnetHdr.GSOSize)
	}
	return p.sizes[:numSegments], true
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
	tsoModeOff         tsoMode = 0
	tsoModeEcho        tsoMode = 1
	tsoModeSplit       tsoMode = 2
	tsoModeSplitNoCsum tsoMode = 3
)

func (t tsoMode) valid() bool {
	return t >= 0 && t <= 3
}

func (t tsoMode) String() string {
	switch t {
	case tsoModeOff:
		return "off"
	case tsoModeEcho:
		return "echo"
	case tsoModeSplit:
		return "split"
	case tsoModeSplitNoCsum:
		return "split-no-csum"
	default:
		return "unknown"
	}
}

func main() {
	flag.Parse()

	if len(*flagPprofAddr) > 0 {
		go func() {
			log.Fatal(http.ListenAndServe(*flagPprofAddr, nil))
		}()
	}

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

	in := make([]byte, 65535)
	out := make([][]byte, 128)
	for i := 0; i < len(out); i++ {
		out[i] = make([]byte, 65535)
	}
	handler := &packetHandler{
		tunAddr:  tunAddr,
		tunRoute: tunRoute,
		mode:     mode,
		sizes:    make([]int, 128),
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
