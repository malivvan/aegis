package scard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/malivvan/aegis/pcsc"
)

const (
	// Scope
	SCOPE_USER     = pcsc.CARD_SCOPE_USER
	SCOPE_TERMINAL = pcsc.CARD_SCOPE_TERMINAL
	SCOPE_SYSTEM   = pcsc.CARD_SCOPE_SYSTEM
)

type ATR []byte

// Return string form of ATR.
func (atr ATR) String() string {
	var buffer bytes.Buffer
	for _, b := range atr {
		buffer.WriteString(fmt.Sprintf("%02x", b))
	}
	return buffer.String()
}

// AID represents an application identifier.
type AID []byte

var (
	// https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-73-4.pdf
	AidPIV = concat(RidNIST[:], 0x00, 0x00, 0x10, 0x00)

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
	AidOpenPGP = concat(RidFSFE[:], 0x01)

	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#nfc-applet-selection
	AidFIDO = concat(RidFIDO[:], 0x2f, 0x00, 0x01)

	// https://github.com/Yubico/yubikey-manager/blob/6496393f9269e86fb7b4b67907b397db33b50c2d/yubikit/core/smartcard.py#L66
	AidYubicoOTP           = concat(RidYubico[:], 0x20, 0x01)
	AidYubicoManagement    = concat(RidYubico[:], 0x47, 0x11, 0x17)
	AidYubicoOATH          = concat(RidYubico[:], 0x21, 0x01)
	AidYubicoHSMAuth       = concat(RidYubico[:], 0x21, 0x07, 0x01)
	AidSolokeysAdmin       = concat(RidSolokeys[:], 0x00, 0x00, 0x00, 0x01)
	AidSolokeysProvisioner = concat(RidSolokeys[:], 0x01, 0x00, 0x00, 0x01)
	AidCardManager         = concat(RidGlobalPlatform[:], 0x00, 0x00, 0x00)
	AidNDEF                = concat(RidNXPNFC[:], 0x01, 0x01)
)

func (c *Card) Select(aid AID) error {
	_, err := c.Transmit(APDU{Cla: 0, Ins: 0xa4, P1: 0x04, P2: 0, Data: aid})
	return err
}

// RID represents a registered application provider identifier.
type RID [5]byte

var (
	// https://www.eftlab.com/knowledge-base/complete-list-of-registered-application-provider-identifiers-rid
	RidNIST           = RID{0xa0, 0x00, 0x00, 0x03, 0x08}
	RidFSFE           = RID{0xd2, 0x76, 0x00, 0x01, 0x24}
	RidYubico         = RID{0xa0, 0x00, 0x00, 0x05, 0x27}
	RidFIDO           = RID{0xa0, 0x00, 0x00, 0x06, 0x47}
	RidSolokeys       = RID{0xA0, 0x00, 0x00, 0x08, 0x47}
	RidGlobalPlatform = RID{0xa0, 0x00, 0x00, 0x01, 0x51}
	RidNXPNFC         = RID{0xD2, 0x76, 0x00, 0x00, 0x85}
)

var ridMap = map[RID]string{
	RidNIST:           "NIST",
	RidFSFE:           "FSFE",
	RidYubico:         "Yubico",
	RidFIDO:           "FIDO",
	RidSolokeys:       "Solokeys",
	RidGlobalPlatform: "GlobalPlatform",
	RidNXPNFC:         "NXP NFC",
}

func (r RID) String() string {
	if s, ok := ridMap[r]; ok {
		return s
	}
	return "<unknown>"
}

// APDU represents an application data unit sent to a smart-card.
type APDU struct {
	Cla  uint8  // Class
	Ins  uint8  // Instruction
	P1   uint8  // Parameter 1
	P2   uint8  // Parameter 2
	Data []byte // Command data
	Len  uint8  // Command data length
	Pib  bool   // Padding indicator byte present
	Elf  bool   // Use extended length fields
}

var (
	ErrRespTooShort                        = errors.New("response too short")
	ErrUnspecifiedWarning                  = errors.New("no information given (warning)")
	ErrUnspecifiedWarningModified          = errors.New("no information given (warning), on-volatile memory has changed")
	ErrUnspecifiedError                    = errors.New("no information given (error)")
	ErrUnspecifiedErrorModified            = errors.New("no information given (error), on-volatile memory has changed")
	ErrWrongLength                         = errors.New("wrong length; no further indication")
	ErrUnsupportedFunction                 = errors.New("function in CLA not supported")
	ErrCommandNotAllowed                   = errors.New("command not allowed")
	ErrWrongParamsNoInfo                   = errors.New("no information given (error)")
	ErrWrongParams                         = errors.New("wrong parameters P1-P2")
	ErrUnsupportedInstruction              = errors.New("instruction code not supported or invalid")
	ErrUnsupportedClass                    = errors.New("class not supported")
	ErrNoDiag                              = errors.New("no precise diagnosis")
	ErrResponseMayBeCorrupted              = errors.New("part of returned data may be corrupted")
	ErrEOF                                 = errors.New("end of file or record reached before reading Ne bytes")
	ErrSelectedFileDeactivated             = errors.New("selected file deactivated")
	ErrInvalidFileControlInfo              = errors.New("file control information not formatted according to 5.3.3")
	ErrSelectedFileInTermination           = errors.New("selected file in termination state")
	ErrNoSensorData                        = errors.New("no input data available from a sensor on the card")
	ErrFileFilledUp                        = errors.New("file filled up by the last write")
	ErrImmediateResponseRequired           = errors.New("immediate response required by the card")
	ErrMemory                              = errors.New("memory failure")
	ErrLogicalChannelNotSupported          = errors.New("logical channel not supported")
	ErrSecureMessagingNotSupported         = errors.New("secure messaging not supported")
	ErrExpectedLastCommand                 = errors.New("last command of the chain expected")
	ErrCommandChainingNotSupported         = errors.New("command chaining not supported")
	ErrCommandIncompatibleWithFile         = errors.New("command incompatible with file structure")
	ErrSecurityStatusNotSatisfied          = errors.New("security status not satisfied")
	ErrAuthenticationMethodBlocked         = errors.New("authentication method blocked")
	ErrReferenceDataNotUsable              = errors.New("reference data not usable")
	ErrConditionsOfUseNotSatisfied         = errors.New("conditions of use not satisfied")
	ErrCommandNotAllowedNoCurrentEF        = errors.New("command not allowed (no current EF)")
	ErrExpectedSecureMessaging             = errors.New("expected secure messaging data objects missing")
	ErrIncorrectSecureMessagingDataObjects = errors.New("incorrect secure messaging data objects")
	ErrIncorrectData                       = errors.New("incorrect parameters in the command data field")
	ErrFunctionNotSupported                = errors.New("function not supported")
	ErrFileOrAppNotFound                   = errors.New("file or application not found")
	ErrRecordNotFound                      = errors.New("record not found")
	ErrNoSpace                             = errors.New("not enough memory space in the file")
	ErrInvalidNcWithTLV                    = errors.New("nc inconsistent with TLV structure")
	ErrIncorrectParams                     = errors.New("incorrect parameters P1-P2")
	ErrInvalidNcWithParams                 = errors.New("nc inconsistent with parameters P1-P2")
	ErrReferenceNotFound                   = errors.New("referenced data or reference data not found (exact meaning depending on the command)")
	ErrFileAlreadyExists                   = errors.New("file already exists")
	ErrNameAlreadyExists                   = errors.New("DF name already exists")
)

var errorCodes = map[[2]byte]error{
	[2]byte{0x90, 0x00}: nil,
	[2]byte{0x62, 0x00}: ErrUnspecifiedWarning,
	[2]byte{0x63, 0x00}: ErrUnspecifiedWarningModified,
	[2]byte{0x64, 0x00}: ErrUnspecifiedError,
	[2]byte{0x65, 0x00}: ErrUnspecifiedErrorModified,
	[2]byte{0x67, 0x00}: ErrWrongLength,
	[2]byte{0x68, 0x00}: ErrUnsupportedFunction,
	[2]byte{0x69, 0x00}: ErrCommandNotAllowed,
	[2]byte{0x6A, 0x00}: ErrWrongParamsNoInfo,
	[2]byte{0x6B, 0x00}: ErrWrongParams,
	[2]byte{0x6D, 0x00}: ErrUnsupportedInstruction,
	[2]byte{0x6E, 0x00}: ErrUnsupportedClass,
	[2]byte{0x6F, 0x00}: ErrNoDiag,
	[2]byte{0x62, 0x81}: ErrResponseMayBeCorrupted,
	[2]byte{0x62, 0x82}: ErrEOF,
	[2]byte{0x62, 0x83}: ErrSelectedFileDeactivated,
	[2]byte{0x62, 0x84}: ErrInvalidFileControlInfo,
	[2]byte{0x62, 0x85}: ErrSelectedFileInTermination,
	[2]byte{0x62, 0x86}: ErrNoSensorData,
	[2]byte{0x63, 0x81}: ErrFileFilledUp,
	[2]byte{0x64, 0x01}: ErrImmediateResponseRequired,
	[2]byte{0x65, 0x81}: ErrMemory,
	[2]byte{0x68, 0x81}: ErrLogicalChannelNotSupported,
	[2]byte{0x68, 0x82}: ErrSecureMessagingNotSupported,
	[2]byte{0x68, 0x83}: ErrExpectedLastCommand,
	[2]byte{0x68, 0x84}: ErrCommandChainingNotSupported,
	[2]byte{0x69, 0x81}: ErrCommandIncompatibleWithFile,
	[2]byte{0x69, 0x82}: ErrSecurityStatusNotSatisfied,
	[2]byte{0x69, 0x83}: ErrAuthenticationMethodBlocked,
	[2]byte{0x69, 0x84}: ErrReferenceDataNotUsable,
	[2]byte{0x69, 0x85}: ErrConditionsOfUseNotSatisfied,
	[2]byte{0x69, 0x86}: ErrCommandNotAllowedNoCurrentEF,
	[2]byte{0x69, 0x87}: ErrExpectedSecureMessaging,
	[2]byte{0x69, 0x88}: ErrIncorrectSecureMessagingDataObjects,
	[2]byte{0x6A, 0x80}: ErrIncorrectData,
	[2]byte{0x6A, 0x81}: ErrFunctionNotSupported,
	[2]byte{0x6A, 0x82}: ErrFileOrAppNotFound,
	[2]byte{0x6A, 0x83}: ErrRecordNotFound,
	[2]byte{0x6A, 0x84}: ErrNoSpace,
	[2]byte{0x6A, 0x85}: ErrInvalidNcWithTLV,
	[2]byte{0x6A, 0x86}: ErrIncorrectParams,
	[2]byte{0x6A, 0x87}: ErrInvalidNcWithParams,
	[2]byte{0x6A, 0x88}: ErrReferenceNotFound,
	[2]byte{0x6A, 0x89}: ErrFileAlreadyExists,
	[2]byte{0x6A, 0x8A}: ErrNameAlreadyExists,
}

func (c *Card) Transmit(apdu APDU) ([]byte, error) {
	resp := make([]byte, 258)
	cmd := new(bytes.Buffer)
	if _, err := cmd.Write([]byte{apdu.Cla, apdu.Ins, apdu.P1, apdu.P2}); err != nil { // write 4 header bytes to buffer
		return nil, err
	}
	if len(apdu.Data) > 0 { // if a payload exists, calculate the length, prepend it to the payload, and write to buffer
		lc := len(apdu.Data)
		if apdu.Pib { // subtract one byte from length if padding indicator byte present
			lc--
		}
		if apdu.Elf { // check if extended length fields (3 bytes) should be used
			lcElf := make([]byte, 2)
			binary.BigEndian.PutUint16(lcElf, uint16(lc))
			if _, err := cmd.Write(append([]byte{0}, lcElf...)); err != nil {
				return nil, err
			}
		} else {
			if _, err := cmd.Write([]byte{uint8(lc)}); err != nil {
				return nil, err
			}
		}
		if _, err := cmd.Write(apdu.Data); err != nil {
			return nil, err
		}
	}
	if _, err := cmd.Write([]byte{apdu.Len}); err != nil {
		return nil, err
	}
	n, err := c.context.client.Transmit(c.cardID, c.protocol, cmd.Bytes(), resp)
	if err != nil {
		return nil, err
	}
	resp = resp[:n]
	if len(resp) < 2 {
		return nil, ErrRespTooShort
	}
	if err = errorCodes[[2]byte{resp[len(resp)-2], resp[len(resp)-1]}]; err != nil {
		return nil, err
	}
	return resp[:len(resp)-2], nil
}

func concat(prefix []byte, rest ...byte) (r []byte) {
	r = append(r, prefix...)
	return append(r, rest...)
}
