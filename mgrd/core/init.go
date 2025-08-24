package core

import (
	"github.com/malivvan/aegis/mgrd/memcall"
)

func init() {
	memcall.DisableCoreDumps()
}
