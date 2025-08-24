//go:build windows

package hid

import (
	"errors"
	"fmt"
	"iter"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"
)

var _ Conn = (*WinHidConn)(nil)

// WinHidConn implements Conn using Windows hid.dll Feature Reports.
type WinHidConn struct {
	h        windows.Handle
	reportID byte
	featLen  uint32 // full feature report length (includes report ID)
	mu       sync.Mutex
}

// Open opens a Windows HID device (SetupAPI path) for OTP Feature Reports.
func (dev *Device) Open() (*WinHidConn, error) {
	devPath := windows.StringToUTF16Ptr(dev.Path)

	hFile, err := windows.CreateFile(
		devPath,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0, // non-overlapped is fine for HidD_* APIs
		0,
	)
	if err != nil {
		return nil, err
	}

	featLen, err := queryFeatureReportLength(hFile)
	if err != nil {
		_ = windows.Close(hFile)
		return nil, err
	}
	if featLen < 1+FEATURE_RPT_SIZE {
		_ = windows.Close(hFile)
		return nil, fmt.Errorf("feature report too small: %d, need >= %d", featLen, 1+FEATURE_RPT_SIZE)
	}

	return &WinHidConn{
		h:        hFile,
		reportID: 0x00, // OTP uses report ID 0
		featLen:  featLen,
	}, nil
}

func (c *WinHidConn) Close() error {
	return windows.Close(c.h)
}

// Receive gets an 8-byte feature report payload (without the report ID).
func (c *WinHidConn) Receive() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	buf := make([]byte, c.featLen)
	buf[0] = c.reportID // report ID must be set for HidD_GetFeature

	if err := hidDGetFeature(c.h, buf); err != nil {
		return nil, err
	}

	// Return only the first 8 bytes of the payload.
	return append([]byte(nil), buf[1:1+FEATURE_RPT_SIZE]...), nil
}

// Send writes an 8-byte feature report payload (without the report ID).
func (c *WinHidConn) Send(data []byte) error {
	if len(data) != FEATURE_RPT_SIZE {
		return fmt.Errorf("send expects %d bytes, got %d", FEATURE_RPT_SIZE, len(data))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	buf := make([]byte, c.featLen)
	buf[0] = c.reportID
	copy(buf[1:], data)

	return hidDSetFeature(c.h, buf)
}

func Enumerate() iter.Seq2[*Device, error] {
	return func(yield func(device *Device, err error) bool) {
		guid, err := getHidGuid()
		if err != nil {
			yield(nil, err)
			return
		}
		deviceInfoSet, err := setupDiGetClassDevs(
			guid,
			"",
			0,
			windows.DIGCF_PRESENT|windows.DIGCF_DEVICEINTERFACE,
		)
		if err != nil {
			yield(nil, err)
			return
		}
		for interfaceMemberIndex := uint32(0); ; interfaceMemberIndex++ {
			deviceInterfaceData, err := setupDiEnumDeviceInterfaces(
				deviceInfoSet,
				nil,
				guid,
				interfaceMemberIndex,
			)
			if err != nil {
				if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
					return
				}
				yield(nil, err)
				return
			}
			deviceInterfaceDetailData, deviceInfoData, err := setupDiGetDeviceInterfaceDetailW(
				deviceInfoSet,
				deviceInterfaceData,
			)
			if err != nil {
				yield(nil, err)
				return
			}
			propertyType, statusBuf, err := setupDiGetDevicePropertyW(deviceInfoSet, deviceInfoData, &windows.DEVPROPKEY{
				FmtID: windows.DEVPROPGUID(windows.GUID{Data1: 0x4340a6c5, Data2: 0x93fa, Data3: 0x4706, Data4: [8]byte{0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7}}),
				PID:   2,
			})
			if err != nil {
				yield(nil, err)
				return
			}
			if propertyType != windows.DEVPROP_TYPE_UINT32 {
				yield(nil, errors.New("uint32 was expected"))
			}
			status := *(*uint32)(unsafe.Pointer(&statusBuf[0]))
			if (status&dnHasProblem) == dnHasProblem ||
				(status&dnStarted) != dnStarted ||
				(status&dnDriverLoaded) != dnDriverLoaded {
				continue
			}
			devicePath := windows.UTF16PtrToString(&deviceInterfaceDetailData.DevicePath[0])
			devicePathPtr := windows.StringToUTF16Ptr(devicePath)
			hFile, err := windows.CreateFile(devicePathPtr, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
			if err != nil {
				yield(nil, err)
				return
			}
			device := &Device{Path: devicePath, InterfaceNbr: int(interfaceMemberIndex)}
			attrs, err := getAttributes(hFile)
			if err != nil {
				yield(nil, err)
				return
			}
			device.VendorID = attrs.VendorID
			device.ProductID = attrs.ProductID
			device.ReleaseNbr = attrs.VersionNumber
			decoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
			mfrStr, _ := getManufacturerString(hFile)
			if len(mfrStr) > 0 {
				device.MfrStr, err = decoder.String(strings.TrimRight(string(mfrStr), string([]byte{0})) + "\u0000")
				if err != nil {
					yield(nil, err)
					return
				}
			}
			productStr, _ := getProductString(hFile)
			if len(mfrStr) > 0 {
				device.ProductStr, err = decoder.String(strings.TrimRight(string(productStr), string([]byte{0})) + "\u0000")
				if err != nil {
					yield(nil, err)
					return
				}
			}
			serialNumberStr, _ := getSerialNumberString(hFile)
			if len(serialNumberStr) > 0 {
				device.SerialNbr, err = decoder.String(strings.TrimRight(string(serialNumberStr), string([]byte{0})) + "\u0000")
				if err != nil {
					yield(nil, err)
					return
				}
			}
			if err := func() error {
				preparsedData, err := getPreparsedData(hFile)
				if err != nil {
					return err
				}
				defer func() {
					_ = freePreparsedData(preparsedData)
				}()
				caps, err := getCaps(preparsedData)
				if err != nil {
					return err
				}
				device.UsagePage = caps.UsagePage
				device.Usage = caps.Usage
				return nil
			}(); err != nil {
				yield(nil, err)
				return
			}
			if !yield(device, nil) {
				return
			}
		}
	}
}

// --- hid.dll interop ---

var (
	modHid                               = windows.NewLazySystemDLL("hid.dll")
	procHidD_GetPreparsedData            = modHid.NewProc("HidD_GetPreparsedData")
	procHidD_FreePreparsedData           = modHid.NewProc("HidD_FreePreparsedData")
	procHidP_GetCaps                     = modHid.NewProc("HidP_GetCaps")
	procHidD_GetFeature                  = modHid.NewProc("HidD_GetFeature")
	procHidD_SetFeature                  = modHid.NewProc("HidD_SetFeature")
	procHidD_GetHidGuid                  = modHid.NewProc("HidD_GetHidGuid")
	procHidD_GetAttributes               = modHid.NewProc("HidD_GetAttributes")
	procHidD_GetManufacturerString       = modHid.NewProc("HidD_GetManufacturerString")
	procHidD_GetProductString            = modHid.NewProc("HidD_GetProductString")
	procHidD_GetSerialNumberString       = modHid.NewProc("HidD_GetSerialNumberString")
	modSetupapi                          = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiGetClassDevsW             = modSetupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiEnumDeviceInterfaces      = modSetupapi.NewProc("SetupDiEnumDeviceInterfaces")
	procSetupDiGetDeviceInterfaceDetailW = modSetupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")
	procSetupDiGetDevicePropertyW        = modSetupapi.NewProc("SetupDiGetDevicePropertyW")
)

const (
	hidpStatusSuccess = 0x00110000
	dnDriverLoaded    = 0x00000002
	dnStarted         = 0x00000008
	dnHasProblem      = 0x00000400
)

type hidpPreparsedData uintptr

type hidpCaps struct {
	Usage                     uint16
	UsagePage                 uint16
	InputReportByteLength     uint16
	OutputReportByteLength    uint16
	FeatureReportByteLength   uint16
	Reserved                  [17]uint16
	NumberLinkCollectionNodes uint16
	NumberInputButtonCaps     uint16
	NumberInputValueCaps      uint16
	NumberInputDataIndices    uint16
	NumberOutputButtonCaps    uint16
	NumberOutputValueCaps     uint16
	NumberOutputDataIndices   uint16
	NumberFeatureButtonCaps   uint16
	NumberFeatureValueCaps    uint16
	NumberFeatureDataIndices  uint16
}

type spDeviceInterfaceData struct {
	CbSize             uint32
	InterfaceClassGuid guid
	Flags              uint32
	Reserved           uint64
}
type hDeviceInfo *byte
type spDeviceInfoData struct {
	CbSize    uint32
	ClassGuid guid
	DevInst   uint32
	Reserved  uint64
}
type spDeviceInterfaceDetailData struct {
	CbSize     uint32
	DevicePath [1]uint16
	Pad_cgo_0  [2]byte
}

type phidpPreparsedData uintptr

type hidAttributes struct {
	Size          uint32
	VendorID      uint16
	ProductID     uint16
	VersionNumber uint16
	Pad_cgo_0     [2]byte
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

func hidDGetPreparsedData(h windows.Handle) (hidpPreparsedData, error) {
	var ppd hidpPreparsedData
	r1, _, err := procHidD_GetPreparsedData.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&ppd)),
	)
	if r1 == 0 {
		return 0, err
	}
	return ppd, nil
}

func hidDFreePreparsedData(ppd hidpPreparsedData) error {
	r1, _, err := procHidD_FreePreparsedData.Call(uintptr(ppd))
	if r1 == 0 {
		return err
	}
	return nil
}

func hidPGetCaps(ppd hidpPreparsedData, caps *hidpCaps) error {
	r1, _, err := procHidP_GetCaps.Call(
		uintptr(ppd),
		uintptr(unsafe.Pointer(caps)),
	)
	if r1 != hidpStatusSuccess {
		return err
	}
	return nil
}

func hidDGetFeature(h windows.Handle, buf []byte) error {
	if len(buf) == 0 {
		return fmt.Errorf("GetFeature: empty buffer")
	}
	r1, _, err := procHidD_GetFeature.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(uint32(len(buf))),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func hidDSetFeature(h windows.Handle, buf []byte) error {
	if len(buf) == 0 {
		return fmt.Errorf("SetFeature: empty buffer")
	}
	r1, _, err := procHidD_SetFeature.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(uint32(len(buf))),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func queryFeatureReportLength(h windows.Handle) (uint32, error) {
	ppd, err := hidDGetPreparsedData(h)
	if err != nil {
		return 0, err
	}
	defer func() { _ = hidDFreePreparsedData(ppd) }()

	var caps hidpCaps
	if err := hidPGetCaps(ppd, &caps); err != nil {
		return 0, err
	}
	return uint32(caps.FeatureReportByteLength), nil
}

func getHidGuid() (*windows.GUID, error) {
	var hidGuid windows.GUID
	_, _, err := procHidD_GetHidGuid.Call(
		uintptr(unsafe.Pointer(&hidGuid)),
	)
	if !errors.Is(err, windows.NOERROR) {
		return nil, err
	}

	return &hidGuid, nil
}

func getAttributes(hidDeviceObject windows.Handle) (*hidAttributes, error) {
	var hidAttrs hidAttributes
	hidAttrs.Size = uint32(unsafe.Sizeof(hidAttrs))
	r1, _, err := procHidD_GetAttributes.Call(
		uintptr(hidDeviceObject),
		uintptr(unsafe.Pointer(&hidAttrs)),
	)
	if r1 == 0 {
		return nil, err
	}

	return &hidAttrs, nil
}

func getManufacturerString(hidDeviceObject windows.Handle) ([]byte, error) {
	buf := make([]byte, 126*2)
	r1, _, err := procHidD_GetManufacturerString.Call(
		uintptr(hidDeviceObject),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return nil, err
	}

	return buf, nil
}

func getPreparsedData(hidDeviceObject windows.Handle) (phidpPreparsedData, error) {
	var preparsedData phidpPreparsedData
	r1, _, err := procHidD_GetPreparsedData.Call(
		uintptr(hidDeviceObject),
		uintptr(unsafe.Pointer(&preparsedData)),
	)
	if r1 == 0 {
		return 0, err
	}

	return preparsedData, nil
}

func freePreparsedData(preparsedData phidpPreparsedData) error {
	r1, _, err := procHidD_FreePreparsedData.Call(
		uintptr(preparsedData),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func getProductString(hidDeviceObject windows.Handle) ([]byte, error) {
	buf := make([]byte, 126*2)
	r1, _, err := procHidD_GetProductString.Call(
		uintptr(hidDeviceObject),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return nil, err
	}
	return buf, nil
}

func getSerialNumberString(hidDeviceObject windows.Handle) ([]byte, error) {
	buf := make([]byte, 126*2)
	r1, _, err := procHidD_GetSerialNumberString.Call(
		uintptr(hidDeviceObject),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return nil, err
	}
	return buf, nil
}

func getCaps(preparsedData phidpPreparsedData) (*hidpCaps, error) {
	var caps hidpCaps
	r1, _, err := procHidP_GetCaps.Call(uintptr(preparsedData), uintptr(unsafe.Pointer(&caps)))
	if r1 != hidpStatusSuccess {
		return nil, err
	}
	return &caps, nil
}

func setupDiGetClassDevs(guid *windows.GUID, enumerator string, hwndParent windows.Handle, flags windows.DIGCF) (hDeviceInfo, error) {
	var enumeratorW *uint16 = nil
	if enumerator != "" {
		enumeratorW = windows.StringToUTF16Ptr(enumerator)
	}
	r1, _, err := procSetupDiGetClassDevsW.Call(
		uintptr(unsafe.Pointer(guid)),
		uintptr(unsafe.Pointer(enumeratorW)),
		uintptr(hwndParent),
		uintptr(flags),
	)
	if !errors.Is(err, windows.NOERROR) {
		return nil, err
	}
	return hDeviceInfo(unsafe.Pointer(r1)), nil
}

func setupDiEnumDeviceInterfaces(deviceInfoSet hDeviceInfo, devInfoData *spDeviceInfoData, interfaceClassGuid *windows.GUID, memberIndex uint32) (*spDeviceInterfaceData, error) {
	var deviceInterfaceData spDeviceInterfaceData
	deviceInterfaceData.CbSize = uint32(unsafe.Sizeof(deviceInterfaceData))
	r1, _, err := procSetupDiEnumDeviceInterfaces.Call(
		uintptr(unsafe.Pointer(deviceInfoSet)),
		uintptr(unsafe.Pointer(devInfoData)),
		uintptr(unsafe.Pointer(interfaceClassGuid)),
		uintptr(memberIndex),
		uintptr(unsafe.Pointer(&deviceInterfaceData)),
	)
	if r1 == 0 {
		return nil, err
	}
	return &deviceInterfaceData, nil
}

func setupDiGetDeviceInterfaceDetailW(deviceInfoSet hDeviceInfo, deviceInterfaceData *spDeviceInterfaceData) (deviceInterfaceDetailData *spDeviceInterfaceDetailData, deviceInfoData *spDeviceInfoData, err error) {
	var requiredSize uint32
	r1, _, err := procSetupDiGetDeviceInterfaceDetailW.Call(
		uintptr(unsafe.Pointer(deviceInfoSet)),
		uintptr(unsafe.Pointer(deviceInterfaceData)),
		0,
		0,
		uintptr(unsafe.Pointer(&requiredSize)),
		uintptr(unsafe.Pointer(deviceInfoData)),
	)
	if r1 == 0 && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, nil, err
	}
	detailDataBuf := make([]byte, requiredSize)
	deviceInterfaceDetailData = (*spDeviceInterfaceDetailData)(unsafe.Pointer(&detailDataBuf[0]))
	deviceInterfaceDetailData.CbSize = uint32(unsafe.Sizeof(*deviceInterfaceDetailData))
	deviceInfoData = new(spDeviceInfoData)
	deviceInfoData.CbSize = uint32(unsafe.Sizeof(*deviceInfoData))
	r1, _, err = procSetupDiGetDeviceInterfaceDetailW.Call(
		uintptr(unsafe.Pointer(deviceInfoSet)),
		uintptr(unsafe.Pointer(deviceInterfaceData)),
		uintptr(unsafe.Pointer(deviceInterfaceDetailData)),
		uintptr(requiredSize),
		uintptr(unsafe.Pointer(&requiredSize)),
		uintptr(unsafe.Pointer(deviceInfoData)),
	)
	if r1 == 0 {
		return nil, nil, err
	}
	return deviceInterfaceDetailData, deviceInfoData, nil
}

func setupDiGetDevicePropertyW(deviceInfoSet hDeviceInfo, deviceInfoData *spDeviceInfoData, devPropKey *windows.DEVPROPKEY) (devPropType windows.DEVPROPTYPE, propertyBuffer []byte, err error) {
	var requiredSize uint32
	r1, _, err := procSetupDiGetDevicePropertyW.Call(
		uintptr(unsafe.Pointer(deviceInfoSet)),
		uintptr(unsafe.Pointer(deviceInfoData)),
		uintptr(unsafe.Pointer(devPropKey)),
		uintptr(unsafe.Pointer(&devPropType)),
		0,
		0,
		uintptr(unsafe.Pointer(&requiredSize)),
		0,
	)
	if r1 == 0 && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return 0, nil, err
	}
	if requiredSize == 0 {
		return 0, nil, errors.New("invalid RequiredSize was returned")
	}
	propertyBuffer = make([]byte, requiredSize)
	r1, _, err = procSetupDiGetDevicePropertyW.Call(
		uintptr(unsafe.Pointer(deviceInfoSet)),
		uintptr(unsafe.Pointer(deviceInfoData)),
		uintptr(unsafe.Pointer(devPropKey)),
		uintptr(unsafe.Pointer(&devPropType)),
		uintptr(unsafe.Pointer(&propertyBuffer[0])),
		uintptr(requiredSize),
		uintptr(unsafe.Pointer(&requiredSize)),
	)
	if r1 == 0 {
		return 0, nil, err
	}
	return devPropType, propertyBuffer, nil
}
