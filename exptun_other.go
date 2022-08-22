//go:build !linux

package main

import (
	"errors"
)

func setupDevice(name string, tso bool) (fd int, err error) {
	return 0, errors.New("unimplemented")
}
