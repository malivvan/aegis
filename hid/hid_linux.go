//go:build linux

package hid

import (
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// HidrawOtpConn implements OtpConnection using Linux hidraw feature report ioctls.
type HidrawOtpConn struct {
	f        *os.File
	fd       int
	reportID byte
	mu       sync.Mutex
}

// Open opens a hidraw path like '/dev/hidraw2' for OTP feature reports.
func (dev *Device) Open() (*HidrawOtpConn, error) {
	f, err := os.OpenFile(dev.Path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &HidrawOtpConn{
		f:        f,
		fd:       int(f.Fd()),
		reportID: 0x00, // OTP interface uses report ID 0
	}, nil
}

func (c *HidrawOtpConn) Close() error {
	return c.f.Close()
}

// Receive gets an 8-byte feature report payload (without the report ID).
func (c *HidrawOtpConn) Receive() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Kernel expects the report ID as the first byte of the buffer.
	buf := make([]byte, 1+FEATURE_RPT_SIZE)
	buf[0] = c.reportID

	req := hidIOC(_IOC_READ|_IOC_WRITE, 'H', 0x07, uintptr(len(buf))) // HIDIOCGFEATURE(len)
	if err := c.ioctl(req, buf); err != nil {
		return nil, err
	}
	// Return only the 8-byte report payload.
	return append([]byte(nil), buf[1:1+FEATURE_RPT_SIZE]...), nil
}

// Send writes an 8-byte feature report payload (without the report ID).
func (c *HidrawOtpConn) Send(data []byte) error {
	if len(data) != FEATURE_RPT_SIZE {
		return fmt.Errorf("send expects %d bytes, got %d", FEATURE_RPT_SIZE, len(data))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Kernel expects the report ID as the first byte of the buffer.
	buf := make([]byte, 1+FEATURE_RPT_SIZE)
	buf[0] = c.reportID
	copy(buf[1:], data)

	req := hidIOC(_IOC_READ|_IOC_WRITE, 'H', 0x06, uintptr(len(buf))) // HIDIOCSFEATURE(len)
	return c.ioctl(req, buf)
}

func Enumerate() iter.Seq2[*Device, error] {
	return func(yield func(device *Device, err error) bool) {
		const sysHidraw = "/sys/class/hidraw"
		
		entries, err := os.ReadDir(sysHidraw)
		if err != nil {
			_ = yield(nil, err)
			return
		}

		for _, e := range entries {
			name := e.Name() // "hidrawX"
			sysPath := filepath.Join(sysHidraw, name)
			devPath := filepath.Join("/dev", name)

			// Resolve the underlying device symlink.
			devLink := filepath.Join(sysPath, "device")
			realDev, err := filepath.EvalSymlinks(devLink)
			if err != nil {
				if !yield(nil, err) {
					return
				}
				continue
			}

			// Find the USB interface directory (contains bInterfaceNumber).
			ifaceDir := realDev
			for {
				if _, err := os.Stat(filepath.Join(ifaceDir, "bInterfaceNumber")); err == nil {
					break
				}
				parent := filepath.Dir(ifaceDir)
				if parent == ifaceDir {
					// Could not locate interface; skip this entry.
					ifaceDir = ""
					break
				}
				ifaceDir = parent
			}
			if ifaceDir == "" {
				// Not a USB HID (could be Bluetooth etc.); skip.
				continue
			}

			// Walk up to the USB device directory (has idVendor/idProduct).
			devDir := ifaceDir
			for {
				if _, err := os.Stat(filepath.Join(devDir, "idVendor")); err == nil {
					break
				}
				parent := filepath.Dir(devDir)
				if parent == devDir {
					devDir = ""
					break
				}
				devDir = parent
			}
			if devDir == "" {
				// Not a USB-backed HID raw device.
				continue
			}

			// Read attributes.
			var d Device
			d.Path = devPath
			d.InterfaceNbr = readHex8(filepath.Join(ifaceDir, "bInterfaceNumber"))

			d.VendorID = readHex16(filepath.Join(devDir, "idVendor"))
			d.ProductID = readHex16(filepath.Join(devDir, "idProduct"))
			d.ReleaseNbr = readHex16(filepath.Join(devDir, "bcdDevice"))

			d.SerialNbr = readString(filepath.Join(devDir, "serial"))
			d.MfrStr = readString(filepath.Join(devDir, "manufacturer"))
			d.ProductStr = readString(filepath.Join(devDir, "product"))

			// Parse HID report descriptor to get top-level Usage Page / Usage.
			// Try both locations as some kernels expose one or the other.
			rdescPaths := []string{
				filepath.Join(sysPath, "device", "report_descriptor"),
				filepath.Join(sysPath, "report_descriptor"),
			}
			for _, p := range rdescPaths {
				if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
					up, u := parseTopLevelUsage(b)
					d.UsagePage, d.Usage = up, u
					break
				}
			}

			if !yield(&d, nil) {
				return
			}
		}
	}
}

// Helpers to read sysfs values.

func readString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readHex16(path string) uint16 {
	s := readString(path)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0
	}
	return uint16(v)
}

func readHex8(path string) int {
	s := readString(path)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 16, 8)
	if err != nil {
		return 0
	}
	return int(v)
}

// parseTopLevelUsage parses the HID report descriptor and returns the Usage Page
// and Usage associated with the first top-level Collection.
func parseTopLevelUsage(desc []byte) (uint16, uint16) {
	var usagePage uint16
	var usage uint16
	i := 0
	for i < len(desc) {
		prefix := desc[i]
		i++

		// Long item
		if prefix == 0xFE {
			if i+2 > len(desc) {
				break
			}
			size := int(desc[i])
			i += 1 // skip data size
			i += 1 // skip long item tag
			i += size
			continue
		}

		sizeCode := int(prefix & 0x03)
		size := 0
		switch sizeCode {
		case 0:
			size = 0
		case 1:
			size = 1
		case 2:
			size = 2
		case 3:
			size = 4
		}
		itemType := (prefix >> 2) & 0x03
		itemTag := (prefix >> 4) & 0x0F

		if i+size > len(desc) {
			break
		}
		var val uint32
		switch size {
		case 1:
			val = uint32(desc[i])
		case 2:
			val = uint32(desc[i]) | uint32(desc[i+1])<<8
		case 4:
			val = uint32(desc[i]) | uint32(desc[i+1])<<8 | uint32(desc[i+2])<<16 | uint32(desc[i+3])<<24
		}
		i += size

		switch itemType {
		case 1: // Global
			if itemTag == 0x0 { // Usage Page
				usagePage = uint16(val & 0xFFFF)
			}
		case 2: // Local
			if itemTag == 0x0 { // Usage
				usage = uint16(val & 0xFFFF)
			}
		case 0: // Main
			if itemTag == 0x0A { // Collection
				// First collection marks the top-level; return what we have.
				return usagePage, usage
			}
		}
	}
	return usagePage, usage
}

func (c *HidrawOtpConn) ioctl(req uintptr, buf []byte) error {
	if len(buf) == 0 {
		return fmt.Errorf("ioctl buffer must not be empty")
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(c.fd), req, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

// ---- Linux _IOC helpers (arch-independent) ----

const (
	_iocNrbits   = 8
	_iocTypebits = 8
	_iocSizebits = 14
	_iocDirbits  = 2

	_iocNrshift   = 0
	_iocTypeshift = _iocNrshift + _iocNrbits
	_iocSizeshift = _iocTypeshift + _iocTypebits
	_iocDirshift  = _iocSizeshift + _iocSizebits

	_IOC_NONE  = 0
	_IOC_WRITE = 1
	_IOC_READ  = 2
)

func _IOC(dir, typ, nr, size uintptr) uintptr {
	return (dir << _iocDirshift) | (typ << _iocTypeshift) | (nr << _iocNrshift) | (size << _iocSizeshift)
}

func hidIOC(dir uintptr, typ byte, nr byte, size uintptr) uintptr {
	return _IOC(dir, uintptr(typ), uintptr(nr), size)
}
