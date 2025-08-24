package mhex

import (
	"bytes"
	"strconv"
	"testing"
)

var testCases = []struct {
	mod  string
	data []byte
}{
	{"", []byte{}},
	{"cc", []byte{0x00}},
	{"cbdefghijklnrtuv", []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}},
	{"krrnrtuvkrrnrtuvkrrnrtuvkrrnrtuv", []byte{0x9c, 0xcb, 0xcd, 0xef, 0x9c, 0xcb, 0xcd, 0xef, 0x9c, 0xcb, 0xcd, 0xef, 0x9c, 0xcb, 0xcd, 0xef}},
}

func TestDecode(t *testing.T) {
	for i, tc := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			data, err := Decode(tc.mod)
			if err != nil {
				t.Errorf("Decode(%q) unexpected error: %v", tc.mod, err)
				return
			}
			if !bytes.Equal(data, tc.data) {
				t.Errorf("Decode(%q) = %#v; want %#v", tc.mod, data, tc.data)
				return
			}
		})
	}
}
func TestEncode(t *testing.T) {
	for i, tc := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			mod := Encode(tc.data)
			if mod != tc.mod {
				t.Errorf("Encode(%#v) = %q; want %q", tc.data, mod, tc.mod)
				return
			}
		})
	}
}
