package main

import (
	"os"

	"github.com/malivvan/aegis/cli"
)

var version = ""

func main() {
	if err := cli.New(func() string {
		if version == "" {
			return "dev"
		}
		return version
	}()).Execute(); err != nil {
		println("error: " + err.Error())
		os.Exit(1)
	}
}
