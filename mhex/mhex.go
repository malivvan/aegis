package mhex

import "fmt"

var stdEncoding = New("cbdefghijklnrtuv")

func Encode(data []byte) string {
	return stdEncoding.Encode(data)
}

func Decode(s string) ([]byte, error) {
	return stdEncoding.Decode(s)
}

type Encoding []byte

func New(alphabet string) Encoding {
	encoding := []byte(alphabet)
	if len(encoding) != 16 {
		panic("modhex alphabet length must be 16")
	}
	return encoding
}

func (encoding Encoding) Encode(data []byte) string {
	out := make([]byte, len(data)*2)
	for i, b := range data {
		out[i*2] = encoding[b>>4]
		out[i*2+1] = encoding[b&0x0F]
	}
	return string(out)
}

func (encoding Encoding) Decode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("length must be multiple of 2")
	}
	index := func(c byte) (int, error) {
		for i := 0; i < len(encoding); i++ {
			if encoding[i] == c {
				return i, nil
			}
		}
		return -1, fmt.Errorf("invalid modhex char: %q", c)
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, err := index(s[i])
		if err != nil {
			return nil, err
		}
		lo, err := index(s[i+1])
		if err != nil {
			return nil, err
		}
		out[i/2] = byte((hi<<4 | lo) & 0xFF)
	}
	return out, nil
}
