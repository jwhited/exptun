package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"log"
)

func setupDevice(name string, tso bool) (fd int, err error) {
	fd, err = unix.Open(tunPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}

	iffIfreq, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}

	// Flags are stored as a uint16 in the ifreq union.
	iffIfreq.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, iffIfreq); err != nil {
		return 0, fmt.Errorf("ioctlifreq TUNSETIFF err: %v", err)
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		return 0, err
	}

	if tso {
		log.Println("enabling TSO")
		const (
			TUN_F_CSM  = 0x01
			TUN_F_TSO4 = 0x02
		)

		err = unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, TUN_F_CSM|TUN_F_TSO4)
		if err != nil {
			return 0, fmt.Errorf("ioctl TUNSETOFFLOAD err: %v", err)
		}
	}

	return fd, nil
}
