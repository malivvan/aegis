package hid

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Device struct {
	Path         string // Platform-Specific Device Path
	VendorID     uint16 // Device Vendor ID
	ProductID    uint16 // Device Product ID
	SerialNbr    string // Serial Number
	ReleaseNbr   uint16 // Device Version Number
	MfrStr       string // Manufacturer String
	ProductStr   string // Product String
	UsagePage    uint16 // Usage Page for Device/Interface
	Usage        uint16 // Usage for Device/Interface
	InterfaceNbr int    // USB Interface Number
}

const (
	FEATURE_RPT_SIZE                    = 8
	FEATURE_RPT_DATA_SIZE               = FEATURE_RPT_SIZE - 1
	SLOT_DATA_SIZE                      = 64
	FRAME_SIZE                          = SLOT_DATA_SIZE + 6
	RESP_PENDING_FLAG                   = 0x40 // response pending
	SLOT_WRITE_FLAG                     = 0x80 // write flag
	RESP_TIMEOUT_WAIT_FLAG              = 0x20 // waiting for touch/timeout
	DUMMY_REPORT_WRITE                  = 0x8F // not used directly here, kept for parity
	SEQUENCE_MASK                       = 0x1F
	STATUS_OFFSET_PROG_SEQ              = 0x4
	STATUS_OFFSET_TOUCH_LOW             = 0x5
	CONFIG_SLOTS_PROGRAMMED_MASK        = 0b00000011
	STATUS_PROCESSING                   = 1
	STATUS_UPNEEDED                     = 2
	CRC_OK_RESIDUAL              uint16 = 0xF0B8
)

// Conn representing an 8-byte HID feature report connection.
type Conn interface {
	Receive() ([]byte, error) // must return exactly 8 bytes
	Send([]byte) error        // must accept exactly 8 bytes
	Close() error
}

// Version struct parsed from 3 bytes.
type Version struct {
	Major, Minor, Patch uint8
}

func VersionFromBytes(b []byte) (Version, error) {
	if len(b) < 3 {
		return Version{}, fmt.Errorf("version bytes too short: %d", len(b))
	}
	return Version{Major: b[0], Minor: b[1], Patch: b[2]}, nil
}

type CommandRejectedError struct{ msg string }

func (e *CommandRejectedError) Error() string {
	return fmt.Sprintf("command rejected: %s", e.msg)
}

type TimeoutError struct{ msg string }

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("timeout: %s", e.msg)
}

// CRC-16/IBM (refin/refout) matching Python implementation.
func calculateCRC(data []byte) uint16 {
	var crc uint16 = 0xFFFF
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			j := crc & 1
			crc >>= 1
			if j == 1 {
				crc ^= 0x8408
			}
		}
	}
	return crc & 0xFFFF
}

func checkCRC(data []byte) bool {
	return calculateCRC(data) == CRC_OK_RESIDUAL
}

func shouldSend(packet []byte, seq int) bool {
	if seq == 0 || seq == 9 { // first and last packet
		return true
	}
	for _, b := range packet {
		if b != 0 {
			return true
		}
	}
	return false
}

func formatFrame(slot byte, payload []byte) []byte {
	crc := calculateCRC(payload)
	frame := make([]byte, 0, FRAME_SIZE)
	frame = append(frame, payload...)              // 64
	frame = append(frame, slot)                    // +1
	frame = append(frame, byte(crc), byte(crc>>8)) // +2 (little-endian)
	frame = append(frame, 0, 0, 0)                 // +3
	return frame
}

func isSequenceUpdated(report []byte, prevSeq byte) bool {
	nextSeq := report[STATUS_OFFSET_PROG_SEQ]
	empty := report[STATUS_OFFSET_TOUCH_LOW]&CONFIG_SLOTS_PROGRAMMED_MASK == 0
	return nextSeq == prevSeq+1 || (nextSeq == 0 && prevSeq > 0 && empty)
}

// Keepalive represents a callback function: STATUS_PROCESSING or STATUS_UPNEEDED.
type Keepalive func(int)

// Protocol implements the OTP HID protocol.
type Protocol struct {
	conn    Conn
	Version Version
}

// New initializes and probes the device.
func New(conn Conn) (*Protocol, error) {
	p := &Protocol{conn: conn}
	report, err := p.receive()
	if err != nil {
		return nil, err
	}
	ver, err := VersionFromBytes(report[1:4])
	if err != nil {
		return nil, err
	}
	p.Version = ver

	// For NEO (v3.x), force applet comm to refresh pgmSeq by sending an invalid scan map.
	if p.Version.Major == 3 {
		_, err := p.SendAndReceive(context.Background(), 0x12, bytesRepeat('c', 51), nil)
		if err != nil {
			var cre *CommandRejectedError
			if !errors.As(err, &cre) {
				// Other errors are propagated.
				return nil, err
			}
		}
	}
	return p, nil
}

func (p *Protocol) Close() error { return p.conn.Close() }

// SendAndReceive sends a command to a slot and returns either data (with CRC) or updated status bytes.
// Pass a cancellable context to abort; onKeepalive receives STATUS_PROCESSING or STATUS_UPNEEDED.
func (p *Protocol) SendAndReceive(ctx context.Context, slot byte, data []byte, onKeepalive Keepalive) ([]byte, error) {
	if onKeepalive == nil {
		onKeepalive = func(int) {}
	}
	payload := make([]byte, SLOT_DATA_SIZE)
	copy(payload, data)
	if len(data) > SLOT_DATA_SIZE {
		return nil, fmt.Errorf("payload too large for HID frame")
	}
	frame := formatFrame(slot, payload)

	progSeq, err := p.sendFrame(frame)
	if err != nil {
		return nil, err
	}
	return p.readFrame(ctx, progSeq, onKeepalive)
}

// ReadStatus returns the 6 status bytes (firmware version is first 3 bytes).
func (p *Protocol) ReadStatus() ([]byte, error) {
	r, err := p.receive()
	if err != nil {
		return nil, err
	}
	// report[1:-1] -> bytes 1..6 inclusive (6 bytes)
	out := make([]byte, 6)
	copy(out, r[1:7])
	return out, nil
}

func (p *Protocol) receive() ([]byte, error) {
	report, err := p.conn.Receive()
	if err != nil {
		return nil, err
	}
	if len(report) != FEATURE_RPT_SIZE {
		return nil, fmt.Errorf("incorrect feature report size: got %d, want %d", len(report), FEATURE_RPT_SIZE)
	}
	return report, nil
}

func (p *Protocol) awaitReadyToWrite() error {
	for i := 0; i < 20; i++ {
		r, err := p.receive()
		if err != nil {
			return err
		}
		if (r[FEATURE_RPT_DATA_SIZE] & SLOT_WRITE_FLAG) == 0 {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for YubiKey to become ready to receive")
}

func (p *Protocol) sendFrame(buf []byte) (byte, error) {
	r, err := p.receive()
	if err != nil {
		return 0, err
	}
	progSeq := r[STATUS_OFFSET_PROG_SEQ]
	seq := 0
	for len(buf) > 0 {
		// Take next 7 bytes.
		n := FEATURE_RPT_DATA_SIZE
		if n > len(buf) {
			n = len(buf)
		}
		chunk := make([]byte, FEATURE_RPT_DATA_SIZE)
		copy(chunk, buf[:n])
		buf = buf[n:]

		if shouldSend(chunk, seq) {
			report := append(chunk, byte(0x80|seq))
			if err := p.awaitReadyToWrite(); err != nil {
				return 0, err
			}
			if err := p.conn.Send(report); err != nil {
				return 0, err
			}
		}
		seq++
	}
	return progSeq, nil
}

func (p *Protocol) readFrame(ctx context.Context, progSeq byte, onKeepalive Keepalive) ([]byte, error) {
	var response []byte
	seq := 0
	needsTouch := false

	for {
		report, err := p.receive()
		if err != nil {
			return nil, err
		}
		status := report[FEATURE_RPT_DATA_SIZE]

		switch {
		case (status & RESP_PENDING_FLAG) != 0:
			// Response packet with sequence.
			if seq == int(status&SEQUENCE_MASK) {
				response = append(response, report[:FEATURE_RPT_DATA_SIZE]...)
				seq++
			} else if (status & SEQUENCE_MASK) == 0 {
				// Transmission complete.
				p.resetState()
				return response, nil
			}
		case status == 0:
			// Status response.
			if len(response) > 0 {
				return nil, fmt.Errorf("incomplete transfer")
			}
			if isSequenceUpdated(report, progSeq) {
				// Return updated status bytes (report[1:7]).
				out := make([]byte, 6)
				copy(out, report[1:7])
				return out, nil
			}
			if needsTouch {
				return nil, &TimeoutError{"timed out waiting for touch"}
			}
			return nil, &CommandRejectedError{"no data"}
		default:
			// Need to wait; provide keepalive and honor cancellation.
			var timeout time.Duration
			if (status & RESP_TIMEOUT_WAIT_FLAG) != 0 {
				onKeepalive(STATUS_UPNEEDED)
				needsTouch = true
				timeout = 100 * time.Millisecond
			} else {
				onKeepalive(STATUS_PROCESSING)
				timeout = 20 * time.Millisecond
			}
			select {
			case <-ctx.Done():
				p.resetState()
				return nil, &TimeoutError{"command cancelled"}
			case <-time.After(timeout):
			}
		}
	}
}

func (p *Protocol) resetState() {
	// Send 7 zero bytes + 0xFF (dummy) to reset read state.
	_ = p.conn.Send([]byte{0, 0, 0, 0, 0, 0, 0, 0xFF})
}

// Helper: repeat a byte n times.
func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
