package scard

import (
	"bytes"
	"encoding/binary"
)

var (
	DoURL            = DataObject{tag: 0x5F50, constructed: false, parent: 0, binary: false, extLen: 2, desc: "URL"}
	DoHistBytes      = DataObject{tag: 0x5F52, constructed: false, parent: 0, binary: true, extLen: 0, desc: "Historical Bytes"}
	DoCardRelData    = DataObject{tag: 0x0065, constructed: true, parent: 0, binary: true, extLen: 0, desc: "Cardholder Related Data"}
	DoName           = DataObject{tag: 0x005B, constructed: false, parent: 0x65, binary: false, extLen: 0, desc: "Name"}
	DoLangPrefs      = DataObject{tag: 0x5F2D, constructed: false, parent: 0x65, binary: false, extLen: 0, desc: "Language preferences"}
	DoSalutation     = DataObject{tag: 0x5F35, constructed: false, parent: 0x65, binary: false, extLen: 0, desc: "Salutation"}
	DoAppRelData     = DataObject{tag: 0x006E, constructed: true, parent: 0, binary: true, extLen: 0, desc: "Application Related Data"}
	DoLoginData      = DataObject{tag: 0x005E, constructed: false, parent: 0, binary: true, extLen: 2, desc: "Login Data"}
	DoAID            = DataObject{tag: 0x004F, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Application Idenfifier (AID)"}
	DoDiscrDOs       = DataObject{tag: 0x0073, constructed: true, parent: 0, binary: true, extLen: 0, desc: "Discretionary Data Objects"}
	DoCardCaps       = DataObject{tag: 0x0047, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Card Capabilities"}
	DoExtLenCaps     = DataObject{tag: 0x00C0, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Extended Card Capabilities"}
	DoAlgoAttrSign   = DataObject{tag: 0x00C1, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Algorithm Attributes Signature"}
	DoAlgoAttrEnc    = DataObject{tag: 0x00C2, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Algorithm Attributes Encryption"}
	DoAlgoAttrAuth   = DataObject{tag: 0x00C3, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Algorithm Attributes Authentication"}
	DoPWStatus       = DataObject{tag: 0x00C4, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Password Status Bytes"}
	DoFingerprints   = DataObject{tag: 0x00C5, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Fingerprints"}
	DoCAFingerprints = DataObject{tag: 0x00C6, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "CA Fingerprints"}
	DoKeyGenDate     = DataObject{tag: 0x00CD, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "Generation times of key pairs"}
	DoSecSuppTmpl    = DataObject{tag: 0x007A, constructed: true, parent: 0, binary: true, extLen: 0, desc: "Security Support Template"}
	DoDigSigCtr      = DataObject{tag: 0x0093, constructed: false, parent: 0x7A, binary: true, extLen: 0, desc: "Digital Signature Counter"}
	DoPrivateDO1     = DataObject{tag: 0x0101, constructed: false, parent: 0, binary: false, extLen: 2, desc: "Private DO 1"}
	DoPrivateDO2     = DataObject{tag: 0x0102, constructed: false, parent: 0, binary: false, extLen: 2, desc: "Private DO 2"}
	DoPrivateDO3     = DataObject{tag: 0x0103, constructed: false, parent: 0, binary: false, extLen: 2, desc: "Private DO 3"}
	DoPrivateDO4     = DataObject{tag: 0x0104, constructed: false, parent: 0, binary: false, extLen: 2, desc: "Private DO 4"}
	DoCardholderCrt  = DataObject{tag: 0x7F21, constructed: true, parent: 0, binary: true, extLen: 1, desc: "Cardholder certificate"}

	// V3.0
	DoGenFeatMgmt = DataObject{tag: 0x7F74, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "General Feature Management"}
	DoAESKeyData  = DataObject{tag: 0x00D5, constructed: false, parent: 0, binary: true, extLen: 0, desc: "AES key data"}
	DoUIFSig      = DataObject{tag: 0x00D6, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "UIF for Signature"}
	DoUIFDec      = DataObject{tag: 0x00D7, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "UIF for Decryption"}
	DoUIFAut      = DataObject{tag: 0x00D8, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "UIF for Authentication"}
	DoUIFAtt      = DataObject{tag: 0x00D8, constructed: false, parent: 0x6E, binary: true, extLen: 0, desc: "UIF for Yubico Attestation key"}
	DoKDFDO       = DataObject{tag: 0x00F9, constructed: false, parent: 0, binary: true, extLen: 0, desc: "KDF data object"}
	DoAlgoInfo    = DataObject{tag: 0x00FA, constructed: false, parent: 0, binary: true, extLen: 2, desc: "Algorithm Information"}
)
var DataObjects = []DataObject{
	DoURL, DoHistBytes, DoCardRelData, DoName, DoLangPrefs, DoSalutation, DoAppRelData, DoLoginData, DoAID, DoDiscrDOs,
	DoCardCaps, DoExtLenCaps, DoAlgoAttrSign, DoAlgoAttrEnc, DoAlgoAttrAuth, DoPWStatus, DoFingerprints, DoCAFingerprints,
	DoKeyGenDate, DoSecSuppTmpl, DoDigSigCtr, DoPrivateDO1, DoPrivateDO2, DoPrivateDO3, DoPrivateDO4, DoCardholderCrt,
	DoGenFeatMgmt, DoAESKeyData, DoUIFSig, DoUIFDec, DoUIFAut, DoUIFAtt, DoKDFDO, DoAlgoInfo,
}

type DataObject struct {
	tag         uint16
	constructed bool
	parent      uint16
	binary      bool
	extLen      uint8
	desc        string
}

func (c *Card) GetChallenge(length uint8) ([]byte, error) {
	return c.Transmit(APDU{Cla: 0, Ins: 0x84, P1: 0, P2: 0, Data: []byte{length}, Len: length})
}

func (do *DataObject) tagBytes() []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(do.tag))
	return b
}

func (do *DataObject) tagP1() byte {
	return do.tagBytes()[0]
}

func (do *DataObject) tagP2() byte {
	return do.tagBytes()[1]
}

func (do *DataObject) parentBytes() []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(do.parent))
	return b
}

func (do *DataObject) children() []DataObject {
	var c []DataObject

	for _, d := range DataObjects {
		if bytes.Equal(d.parentBytes(), do.tagBytes()) {
			c = append(c, d)
		}
	}

	return c
}

// doFindTLV function is based on GnuPG implementation of do_find_tlv in common/tlv.c
func doFindTLV(data []byte, tag uint16, nestLevel int) []byte {
	var o int = 0
	var n int = len(data)
	var tagLen uint16
	var thisTag uint16
	var tagFound bool
	var composite bool

	for !tagFound {
		if n < 2 { // Buffer definitely too short for tag and length.
			return nil
		}

		if data[o] == 0 || data[o] == 0xff { // Skip optional filler between TLV objects.
			o++
			n--
		}

		composite = (data[o] & 0x20) != 0

		if (data[o] & 0x1f) == 0x1f { // more tag bytes to follow
			o++
			n--

			if n < 2 { // Buffer definitely too short for tag and length.
				return nil
			}
			if (data[o] & 0x1f) == 0x1f { // We support only up to 2 bytes.
				return nil
			}

			thisTag = binary.BigEndian.Uint16([]byte{data[o-1], data[o] & 0x7f})
		} else {
			thisTag = binary.BigEndian.Uint16([]byte{0, data[o]})
		}

		tagLen = binary.BigEndian.Uint16([]byte{0, data[o+1]})
		o += 2
		n -= 2
		if tagLen < 0x80 {
			// do nothing
		} else if tagLen == 0x81 { // One byte length follows.
			if n != 0 { // we expected 1 more bytes with the length
				return nil
			}

			tagLen = binary.BigEndian.Uint16([]byte{0, data[o]})
			o++
			n--
		} else if tagLen == 0x82 { // Two byte length follows
			if n < 2 { // We expected 2 more bytes with the length.
				return nil
			}

			tagLen = binary.BigEndian.Uint16([]byte{data[o], data[o+1]})
			o += 2
			n -= 2
		} else { // APDU limit is 65535, thus it does not make sense to assume longer length fields. */
			return nil
		}

		if composite && nestLevel < 100 { // Dive into this composite DO after checking for a too deep nesting
			tmpData := doFindTLV(data[o:], tag, nestLevel+1)

			if len(tmpData) > 0 {
				return tmpData
			}
		}

		if thisTag == tag {
			tagFound = true
		} else if int(tagLen) > n { // Buffer too short to skip to the next tag.
			return nil
		} else {
			o += int(tagLen)
			n -= int(tagLen)
		}
	}

	return data[o : o+int(tagLen)]
}
