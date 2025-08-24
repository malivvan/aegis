package yk

import (
	"context"

	"github.com/malivvan/aegis/hid"
)

const (
	OtpSlot1 byte = 0x30
	OtpSlot2 byte = 0x38
)

type Yubikey struct {
	ctx context.Context
	hid *hid.Protocol
}
