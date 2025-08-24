// Demo code for the Flex primitive.
package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/malivvan/aegis/hid"
	"github.com/malivvan/aegis/scard"
)

func main() {
	if err := run2(); err != nil {
		fmt.Printf("\nerror: %s\n\n", err)
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Printf("\nerror: %s\n\n", err)
		os.Exit(1)
	}

}

type Tag uint

var errInvalidLength = errors.New("invalid length")

type TagValue struct {
	Tag        Tag
	Value      []byte
	Children   TagValues
	SkipLength bool
}

func (t Tag) IsConstructed() bool {
	u := t
	for u > 0xff {
		u >>= 8
	}
	return u&(1<<5) != 0
}

func (tv *TagValue) Equal(w TagValue) bool {
	if !tv.Tag.IsConstructed() {
		return bytes.Equal(tv.Value, w.Value)
	}
	return tv.Children.Equal(w.Children)
}

func New(t Tag, values ...any) (tv TagValue) {
	tv.Tag = t
	for _, value := range values {
		tv.Append(value)
	}
	return tv
}

func (tv *TagValue) Append(value any) {
	switch v := value.(type) {
	case encoding.BinaryMarshaler:
		data, err := v.MarshalBinary()
		if err != nil {
			panic("failed to marshal")
		}
		tv.Value = append(tv.Value, data...)
	case byte:
		tv.Value = append(tv.Value, v)
	case []byte:
		tv.Value = append(tv.Value, v...)
	case string:
		tv.Value = append(tv.Value, []byte(v)...)
	case uint16:
		tv.Value = binary.BigEndian.AppendUint16(tv.Value, v)
	case uint32:
		tv.Value = binary.BigEndian.AppendUint32(tv.Value, v)
	case uint64:
		tv.Value = binary.BigEndian.AppendUint64(tv.Value, v)
	case TagValue:
		tv.Children = append(tv.Children, v)
	case TagValues:
		tv.Children = append(tv.Children, v...)
	}
}

type TagValues []TagValue

func (tvs *TagValues) Get(tag Tag) ([]byte, TagValues, bool) {
	for _, tv := range *tvs {
		if tv.Tag == tag {
			return tv.Value, tv.Children, true
		}
	}
	return nil, nil, false
}

func (tvs *TagValues) Put(tv TagValue) {
	*tvs = append(*tvs, tv)
}

func (tvs *TagValues) Pop(tag Tag) (TagValue, bool) {
	for i, tv := range *tvs {
		if tv.Tag == tag {
			*tvs = slices.Delete(*tvs, i, i+1)
			return tv, true
		}
	}
	return TagValue{}, false
}

func (tvs *TagValues) GetChild(tag Tag, subs ...Tag) ([]byte, TagValues, bool) {
	value, children, ok := tvs.Get(tag)
	if ok {
		if len(subs) > 0 && len(children) > 0 {
			return children.GetChild(subs[0], subs[1:]...)
		}
		return value, children, true
	}
	return nil, nil, false
}

func (tvs *TagValues) GetAll(tag Tag) (s TagValues) {
	for _, tv := range *tvs {
		if tv.Tag == tag {
			s = append(s, tv)
		}
	}
	return s
}

func (tvs *TagValues) DeleteAll(tag Tag) (removed int) {
	var n, r int
	for _, tv := range *tvs {
		if tv.Tag != tag {
			(*tvs)[n] = tv
			n++
		} else {
			r++
		}
	}
	*tvs = (*tvs)[:n]
	return r
}

func (tvs *TagValues) PopAll(tag Tag) (s TagValues) {
	var n int
	for _, tv := range *tvs {
		if tv.Tag != tag {
			(*tvs)[n] = tv
			n++
		} else {
			s = append(s, tv)
		}
	}
	*tvs = (*tvs)[:n]
	return s
}

func (tvs *TagValues) Equal(w TagValues) bool {
	if len(*tvs) != len(w) {
		return false
	}
	for i, vc := range *tvs {
		wc := w[i]

		if !vc.Equal(wc) {
			return false
		}
	}
	return true
}

func DecodeSimple(buf []byte) (tvs TagValues, err error) {
	for len(buf) > 0 {
		if len(buf) < 2 {
			return nil, errInvalidLength
		}
		var o, l int
		if buf[1] != 0xff {
			o = 2
			l = int(buf[1])
		} else {
			if len(buf) < 4 {
				return nil, errInvalidLength
			}
			o = 4
			l = int(buf[2])<<8 + int(buf[3])
			if len(buf) < 4+l {
				return nil, errInvalidLength
			}
		}
		if len(buf) < o+l {
			return nil, errInvalidLength
		}
		tvs = append(tvs, TagValue{Tag: Tag(buf[0]), Value: buf[o : o+l]})
		buf = buf[o+l:]
	}
	return tvs, nil
}

const (
	TagCapsSupportedUSB Tag = 0x01
	TagSerialNumber     Tag = 0x02
	TagCapsEnabledUSB   Tag = 0x03
	TagFormFactor       Tag = 0x04
	TagFirmwareVersion  Tag = 0x05
	TagAutoEjectTimeout Tag = 0x06
	TagChalRespTimeout  Tag = 0x07
	TagDeviceFlags      Tag = 0x08
	TagAppVersions      Tag = 0x09
	TagConfigLock       Tag = 0x0a
	TagUnlock           Tag = 0x0b
	TagReboot           Tag = 0x0c
	TagCapsSupportedNFC Tag = 0x0d
	TagCapsEnabledNFC   Tag = 0x0e
)

type Capability int

const (
	CapOTP     Capability = 0x01
	CapU2F     Capability = 0x02
	CapFIDO2   Capability = 0x200
	CapOATH    Capability = 0x20
	CapPIV     Capability = 0x10
	CapOpenPGP Capability = 0x08
	CapHSMAUTH Capability = 0x100
)

type FormFactor byte

const (
	FormFactorUnknown       FormFactor = 0x00
	FormFactorUSBAKeychain  FormFactor = 0x01
	FormFactorUSBANano      FormFactor = 0x02
	FormFactorUSBCKeychain  FormFactor = 0x03
	FormFactorUSBCNano      FormFactor = 0x04
	FormFactorUSBCLightning FormFactor = 0x05
	FormFactorUSBABio       FormFactor = 0x06
	FormFactorUSBCBio       FormFactor = 0x07
)

var ErrInvalidResponseLength = errors.New("invalid response length")

type DeviceInfo struct {
	Flags            DeviceFlag
	CapsSupportedUSB Capability
	CapsEnabledUSB   Capability
	CapsSupportedNFC Capability
	CapsEnabledNFC   Capability
	SerialNumber     uint32
	FirmwareVersion  Version
	FormFactor       FormFactor
	AutoEjectTimeout time.Duration
	ChalRespTimeout  time.Duration
	IsLocked         bool
	IsSky            bool
	IsFIPS           bool
}
type DeviceFlag byte

const (
	DeviceFlagRemoteWakeup DeviceFlag = 0x40
	DeviceFlagEject        DeviceFlag = 0x80
)

var ErrInvalidVersion = errors.New("invalid version")

// Version encodes a major, minor, and patch version.
type Version struct {
	Major int
	Minor int
	Patch int
}

func ParseVersion(s string) (v Version, err error) {
	var ps []string
	if s != "" {
		ps = strings.Split(s, ".")
	}
	l := len(ps)

	if l > 3 {
		return v, fmt.Errorf("%w: too many dots (%d)", ErrInvalidVersion, l)
	}
	vs := []*int{&v.Major, &v.Minor, &v.Patch}
	for i, q := range vs {
		if i >= l {
			*q = -1
		} else if *q, err = strconv.Atoi(ps[i]); err != nil {
			return v, err
		} else if *q < 0 {
			return v, fmt.Errorf("%w: must be positive", ErrInvalidVersion)
		}
	}
	return v, nil
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v Version) Less(w Version) bool {
	if v.Major != w.Major {
		return v.Major > w.Major
	}
	if v.Minor != w.Minor {
		return v.Minor > w.Minor
	}
	return v.Patch > w.Patch
}

func Unmarshal(b []byte) (*DeviceInfo, error) {
	var di DeviceInfo
	tvs, err := DecodeSimple(b[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	readCap := func(tv TagValue) (Capability, error) {
		switch len(tv.Value) {
		case 1: // For Yubikey 4.x
			return Capability(tv.Value[0]), nil
		case 2:
			return Capability(binary.BigEndian.Uint16(tv.Value)), nil
		default:
			return 0, ErrInvalidResponseLength
		}
	}
	for _, tv := range tvs {
		switch tv.Tag {
		case TagCapsSupportedUSB:
			if di.CapsSupportedNFC, err = readCap(tv); err != nil {
				return nil, fmt.Errorf("%w: CapsSupportedUSB", err)
			}
		case TagCapsEnabledUSB:
			if di.CapsEnabledUSB, err = readCap(tv); err != nil {
				return nil, fmt.Errorf("%w: CapsEnabledUSB", err)
			}
		case TagCapsSupportedNFC:
			if len(tv.Value) != 2 {
				return nil, fmt.Errorf("%w: CapsSupportedNFC", ErrInvalidResponseLength)
			}
			di.CapsSupportedNFC = Capability(binary.BigEndian.Uint16(tv.Value))
		case TagCapsEnabledNFC:
			if len(tv.Value) != 2 {
				return nil, fmt.Errorf("%w: CapsEnabledNFC", ErrInvalidResponseLength)
			}
			di.CapsEnabledNFC = Capability(binary.BigEndian.Uint16(tv.Value))
		case TagSerialNumber:
			if len(tv.Value) != 4 {
				return nil, fmt.Errorf("%w: SerialNumber", ErrInvalidResponseLength)
			}
			di.SerialNumber = binary.BigEndian.Uint32(tv.Value)
		case TagFormFactor:
			if len(tv.Value) != 1 {
				return nil, fmt.Errorf("%w: FormFactor", ErrInvalidResponseLength)
			}
			di.FormFactor = FormFactor(tv.Value[0] & 0xf)
			di.IsFIPS = tv.Value[0]&0x80 != 0
			di.IsSky = tv.Value[0]&0x40 != 0
		case TagFirmwareVersion:
			if len(tv.Value) != 3 {
				return nil, fmt.Errorf("%w: FirmwareVersion", ErrInvalidResponseLength)
			}
			di.FirmwareVersion = Version{Major: int(tv.Value[0]), Minor: int(tv.Value[1]), Patch: int(tv.Value[2])}
		case TagAutoEjectTimeout:
			if len(tv.Value) != 2 {
				return nil, fmt.Errorf("%w: AutoEjectTimeout", ErrInvalidResponseLength)
			}
			di.AutoEjectTimeout = time.Second * time.Duration(binary.BigEndian.Uint16(tv.Value))
		case TagChalRespTimeout:
			if len(tv.Value) != 1 {
				return nil, fmt.Errorf("%w: ChalRespTimeout", ErrInvalidResponseLength)
			}
			di.ChalRespTimeout = time.Second * time.Duration(tv.Value[0])
		case TagDeviceFlags:
			if len(tv.Value) != 1 {
				return nil, fmt.Errorf("%w: DeviceFlags", ErrInvalidResponseLength)
			}
			di.Flags = DeviceFlag(tv.Value[0])
		case TagConfigLock:
			if len(tv.Value) != 1 {
				return nil, fmt.Errorf("%w: ConfigLock", ErrInvalidResponseLength)
			}
			di.IsLocked = tv.Value[0] != 0
		}
	}
	return &di, nil
}

func run2() error {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return err
	}
	defer ctx.Release()
	readers, err := ctx.ListReadersWithCard()
	if err != nil {
		return err
	}
	for _, r := range readers {
		fmt.Printf("Reader: %s\n", r.Name())
		c, err := r.Connect()
		if err != nil {
			return err
		}

		err = c.Select(scard.AidYubicoManagement)
		if err != nil {
			return err
		}
		resp, err := c.Transmit(scard.APDU{
			Ins: 0x1D,
			P1:  0x00,
			P2:  0x00,
		})
		if err != nil {
			return err
		}
		info, err := Unmarshal(resp)
		if err != nil {
			return err
		}
		fmt.Printf("Resp: %+v\n", info)
	}
	return nil
}
func run() error {
	for dev, err := range hid.Enumerate() {
		if err != nil {
			return err
		}
		if dev.VendorID != 4176 || dev.ProductID != 1031 {
			continue
		}
		fmt.Printf("Device: %v\n", dev)

		conn, err := dev.Open()
		if err != nil {
			return err
		}
		defer conn.Close()
		proto, err := hid.New(conn)
		if err != nil {
			return err
		}
		snResp, err := proto.SendAndReceive(context.Background(), 0x10, []byte{}, nil)
		if err != nil {
			return err
		}
		sn := binary.BigEndian.Uint32(snResp[:4])
		fmt.Printf("Serial: %d\n", sn)

		if dev.UsagePage != 61904 {
			continue
		}

		//

		//

		h := sha512.New()
		h.Write([]byte("hello"))
		sum := h.Sum(nil)
		resp, err := proto.SendAndReceive(context.Background(), 0x38, sum, nil)
		if err != nil {
			return err
		}
		fmt.Printf("Digest: %x\n", resp[:20])

		//
		////var secret [40]byte
		////secret[0] = 0x01
		////xx, err := proto.SendAndReceive(context.Background(), 0x01, secret[:], nil)
		////if err != nil {
		////	return err
		////}
		////fmt.Printf("resp: %x\n", xx)
		//// e1600e32b5a511aea843343806e4a7fb7eb9bd2b
		//// e1600e32b5a511aea843343806e4a7fb7eb9bd2b3616000000000000
		//h := sha512.New()
		//h.Write([]byte("hello"))
		//sum := h.Sum(nil)
		//resp, err := proto.Calculate(context.Background(), hid.Slot2, sum)
		//if err != nil {
		//	return err
		//}
		//fmt.Printf("Resp: %x (%d)\n", resp, len(resp))
		//
		////
		////err = writeChunks(dev, []byte("hello"))
		////if err != nil {
		////	return err
		////}
		////_, err = dev.Write([]byte{0x00, 0x30, 0x22, 0x59, 0x00, 0x00, 0x00, 0x89})
		////if err != nil {
		////	return err
		////}
		////
		////_, err = dev.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff})
		////if err != nil {
		////	return err
		////}
		////var buf [8]byte
		////_, err = dev.Read(buf[:])
		////if err != nil {
		////	return err
		////}
		////fmt.Printf("%x\n", buf)
		//return nil
	}
	return nil
}
