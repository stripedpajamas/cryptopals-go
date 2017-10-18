package main

import (
	"flag"
	"fmt"
	"github.com/stripedpajamas/cryptopals/set3/challenge19"
)

func main() {
	var crackServer = flag.Bool("server", false, "Run the challenge 19 server")

	flag.Parse()

	if *crackServer {
		fmt.Println("Starting Challenge 19 crack server on port 8000")
		challenge19.CrackServer()
	}
}
