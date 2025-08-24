// Demo code for the Flex primitive.
package main

import (
	"fmt"
	"os"

	"github.com/malivvan/aegis/scard"
)

func main() {
	if err := run(); err != nil {
		fmt.Printf("\nerror: %s\n\n", err)
		os.Exit(1)
	}

}
func run() error {
	var reader *scard.Reader
	ctx, err := scard.EstablishContext()
	if err != nil {
		return err
	}
	defer ctx.Release()
	readers, err := ctx.ListReadersWithCard()
	if err != nil {
		return err
	}
	if len(readers) == 0 {
		fmt.Println("\nplease insert smart card\n")
		return nil
	}
	if len(readers) == 1 {
		reader = readers[0]
	} else {
		// to do: handle multiple readers choices
		return fmt.Errorf("multiple readers not supported")
	}
	card, err := reader.Connect()
	if err != nil {
		return err
	}
	defer card.Disconnect()

	err = card.Select(scard.AidOpenPGP)
	if err != nil {
		return err
	}
	resp, err := card.GetChallenge(64)
	if err != nil {
		return err
	}
	fmt.Printf("%x\n", resp)
	return nil
}
