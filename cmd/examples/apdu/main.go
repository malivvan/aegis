package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/malivvan/aegis"
)

func main() {
	var script, aid string
	flag.StringVar(&script, "script", "", "script")
	flag.StringVar(&aid, "aid", "", "applet id")
	flag.Usage = func() {
		fmt.Println("\nusage: apdu [ -aid <aid> -script <file> ]\n")
	}
	flag.Parse()
	err := yk.Run(aid, script)
	if err != nil {
		fmt.Printf("\nerror: %s\n\n", err)
		os.Exit(1)
	}
}
