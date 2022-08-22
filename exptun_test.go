package main

import (
	"encoding/hex"
	"testing"
)

func Test_checksum(t *testing.T) {
	testA, _ := hex.DecodeString("4500003c49db400040060000ac10ff02ac10ff01")
	testB, _ := hex.DecodeString("4500003c65e5400040060000ac10ff02ac10ff01")
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want uint16
	}{
		{
			"test A",
			args{
				testA,
			},
			0x9abb,
		},
		{
			"test B",
			args{
				testB,
			},
			0x7eb1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checksum(tt.args.b); got != tt.want {
				t.Errorf("checksum() = %x, want %x", got, tt.want)
			}
		})
	}
}
