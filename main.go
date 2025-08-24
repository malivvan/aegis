package main

import (
	"fmt"
	"log"
	"os"

	"github.com/malivvan/aegis/cli"
	"github.com/malivvan/aegis/cui"
	"github.com/malivvan/aegis/mgrd"
	"github.com/malivvan/aegis/opgp/crypto"
)

func main() {
	mgrd.CatchSignal(func(_ os.Signal) {
		fmt.Println("\nExiting...")
	}, os.Interrupt)
	defer mgrd.Purge()

	pgp := crypto.PGP()
	aliceKeyPriv, err := pgp.KeyGeneration().
		AddUserId("alice", "alice@alice.com").
		New().
		GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	aliceKeyPub, err := aliceKeyPriv.ToPublic()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(aliceKeyPub.Armor())

	if err := (&cli.App{
		Name:  "aegis",
		Usage: "a terminal application for secret management with hardware token support",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "keyring",
				Value:   "~/.aegis.kdbx",
				Usage:   "path to the keyring database",
				EnvVars: []string{"AEGIS_KEYRING"},
			},
		},
		Action: func(ctx *cli.Context) error {
			if ctx.NArg() == 0 {
				return cui.Execute("TODO")
			}
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:  "version",
				Usage: "print the version information",
				Action: func(ctx *cli.Context) error {
					//	fmt.Println(bom.Metadata.Component.Version)
					return nil
				},
			},
		},
	}).Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
