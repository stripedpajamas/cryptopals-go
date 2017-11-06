package main

import (
	"flag"
	"fmt"
	"github.com/stripedpajamas/cryptopals/set3/challenge19"
	"github.com/stripedpajamas/cryptopals/set4/challenge31"
)

func main() {
	var crackServer = flag.Bool("crackServer", false, "Run the challenge 19 server")
	var hmacServer = flag.Bool("hmacServer", false, "Run the challenge 31 server")
	var hmacAttack = flag.String("hmacAttack", "foo", "Run the challenge 31 attacker")

	flag.Parse()

	if *crackServer {
		fmt.Println("Starting Challenge 19 crack server on port 8000")
		challenge19.CrackServer()
	} else if *hmacServer {
		fmt.Println("Starting Challenge 31 HMAC server on port 8000")
		challenge31.HmacServer()
	} else if *hmacAttack != "" {
		fmt.Printf("Starting Challenge 31 HMAC attacker for filename %s\n", *hmacAttack)
		challenge31.DiscoverValidMAC(*hmacAttack, true)
	}
}
