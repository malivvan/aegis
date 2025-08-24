//go:build !windows

package scard

import (
	"time"

	"github.com/malivvan/aegis/pcsc"
)

// Context represents a smart card context required to access readers and cards.
type Context struct {
	client *pcsc.PCSCLiteClient
	ctxID  uint32
}

// EstablishContext establishes a smart card context. (This should be the first function to be called.)
func EstablishContext(scope ...uint32) (*Context, error) {
	var err error
	scp := uint32(SCOPE_SYSTEM)
	if len(scope) > 0 {
		scp = scope[0]
	}
	context := &Context{}
	context.client, err = pcsc.PCSCLiteConnect()
	if err != nil {
		return nil, err
	}
	context.ctxID, err = context.client.EstablishContext(scp)
	if err != nil {
		return nil, err
	}
	return context, nil
}

// Release resources associated with smart card context.
func (ctx *Context) Release() error {
	return ctx.client.ReleaseContext(ctx.ctxID)
}

// ListReaders lists all smart card readers.
func (ctx *Context) ListReaders() ([]*Reader, error) {
	return ctx.listReaders(false)
}

// ListReadersWithCard lists smart card readers with inserted cards.
func (ctx *Context) ListReadersWithCard() ([]*Reader, error) {
	return ctx.listReaders(true)
}

func (ctx *Context) listReaders(withCard bool) ([]*Reader, error) {
	readers, err := ctx.client.ListReaders()
	if err != nil {
		return nil, err
	}
	result := make([]*Reader, 0, len(readers))
	for i := 0; i < len(readers); i++ {
		if withCard {
			if readers[i].IsCardPresent() {
				result = append(result, &Reader{
					context: ctx, reader: *readers[i]})
			}
		} else {
			result = append(result, &Reader{
				context: ctx, reader: *readers[i]})
		}
	}
	return result, nil
}

// WaitForCardPresent blocks until a smart card is inserted into any reader or returns immediately if a card is already
// present.
func (ctx *Context) WaitForCardPresent() (*Reader, error) {
	var reader *Reader
	for reader == nil {
		count, err := ctx.client.SyncReaders()
		if err != nil {
			return nil, err
		}
		for i := uint32(0); i < count; i++ {
			r := ctx.client.Readers()[i]
			if r.IsCardPresent() {
				reader = &Reader{context: ctx, reader: r}
				break
			}
		}
		if reader != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	return reader, nil
}

// Reader represents a smart card reader.
// Note that physical card readers with slots for multiple cards are represented by one Reader instance per slot.
type Reader struct {
	context *Context
	reader  pcsc.Reader
}

// Name returns the name of the card reader.
func (r *Reader) Name() string {
	return r.reader.Name()
}

// IsCardPresent checks if a card is present in the reader.
func (r *Reader) IsCardPresent() bool {
	count, err := r.context.client.SyncReaders()
	if err != nil {
		return false
	}
	readers := r.context.client.Readers()
	for i := uint32(0); i < count; i++ {
		if r.Name() == readers[i].Name() {
			r.reader = readers[i]
			if r.reader.IsCardPresent() {
				return true
			}
		}
	}
	return false
}

// WaitUntilCardRemoved blocks until the card is removed from the reader.
func (r *Reader) WaitUntilCardRemoved() {
	for r.IsCardPresent() {
		time.Sleep(250 * time.Millisecond)
	}
}

// Connect to card.
func (r *Reader) Connect() (*Card, error) {
	cardID, protocol, err := r.context.client.CardConnect(
		r.context.ctxID, r.reader.Name())
	if err != nil {
		return nil, err
	}
	return &Card{
		context:  r.context,
		cardID:   cardID,
		protocol: protocol,
		atr:      r.reader.CardAtr[:r.reader.CardAtrLength],
	}, nil
}

// Card represents a connection to a smart card.
type Card struct {
	context  *Context
	cardID   int32
	protocol uint32
	atr      ATR
}

// ATR returns the card ATR (Answer To Reset).
func (c *Card) ATR() ATR {
	return c.atr
}

// Disconnect from card.
func (c *Card) Disconnect() error {
	err := c.context.client.CardDisconnect(c.cardID)
	if err != nil {
		return err
	}
	return nil
}
