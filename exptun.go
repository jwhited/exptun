package main

import (
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
	flagTunName  = flag.String("tun-name", "exptun", "name of TUN device")
	flagTunAddr  = flag.String("tun-addr", "172.16.255.1/32", "address of TUN device")
	flagTunRoute = flag.String("tun-route", "172.16.255.2/32", "route towards TUN device")
	flagTunTSO   = flag.Bool("tun-tso", false, "enable TSO for TUN device")
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

func natPacket(b []byte, tunAddr, tunRoute netip.Prefix) ([]byte, bool) {
	// NAT packets from address behind TUN device
	if len(b) < 40 {
		return nil, false
	}
	if b[0]>>4 != 4 { // only IPv4 for now
		return nil, false
	}
	if b[0]&0x0F != 5 { // ignore ip options for now
		return nil, false
	}
	if b[9] != unix.IPPROTO_TCP { // ignore non-tcp
		return nil, false
	}
	srcAddr, _ := netip.AddrFromSlice(b[12:16])
	dstAddr, _ := netip.AddrFromSlice(b[16:20])
	if srcAddr.Compare(tunAddr.Addr()) != 0 {
		return nil, false
	}
	if !tunRoute.Contains(dstAddr) {
		return nil, false
	}
	// swap src/dst addrs
	copy(b[12:16], dstAddr.AsSlice())
	copy(b[16:20], srcAddr.AsSlice())

	// IPv4 header checksum
	b[10], b[11] = 0, 0 // clear
	ipv4Csum := checksum(b[:20])
	binary.BigEndian.PutUint16(b[10:12], ipv4Csum)

	// TCP header checksum
	b[20+16], b[20+17] = 0, 0 // clear
	tcpCsumData := make([]byte, 12+len(b[20:]))
	copy(tcpCsumData[:4], b[12:16])   // srcAddr
	copy(tcpCsumData[4:], b[16:20])   // dstAddr
	tcpCsumData[9] = unix.IPPROTO_TCP // protocol
	binary.BigEndian.PutUint16(tcpCsumData[10:], uint16(len(b[20:])))
	copy(tcpCsumData[12:], b[20:])
	tcpCsum := checksum(tcpCsumData)
	binary.BigEndian.PutUint16(b[20+16:], tcpCsum)

	return b, true
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

	fd, err := setupDevice(*flagTunName, *flagTunTSO)
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

	go func() {
		b := make([]byte, 65535)
		for {
			n, err := f.Read(b)
			if err != nil {
				log.Fatalf("error reading from TUN: %v", err)
			}
			if n > 1500 {
				panic(fmt.Sprintf("got packet > 1500 bytes (%d)", n))
			}
			c, ok := natPacket(b[:n], tunAddr, tunRoute)
			if !ok {
				continue
			}
			_, err = f.Write(c)
			if err != nil {
				log.Fatalf("error writing to TUN: %v", err)
			}
		}
	}()

	select {}
}
