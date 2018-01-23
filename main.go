package main

import (
	"flag"
	"fmt"

	"github.com/stripedpajamas/cryptopals/set3/challenge19"
	"github.com/stripedpajamas/cryptopals/set4/challenge31"
	"github.com/stripedpajamas/cryptopals/set4/challenge32"
	"github.com/stripedpajamas/cryptopals/set6/challenge41"
	"github.com/stripedpajamas/cryptopals/set7/challenge50"
)

func main() {
	var crackServer = flag.Bool("crackServer", false, "Run the challenge 19 server")
	var hmacServer = flag.Bool("hmacServer", false, "Run the challenge 31 server (50ms delay)")
	var hmacServer2 = flag.Bool("hmacServer2", false, "Run the challenge 31 server (25ms delay)")
	var hmacAttack = flag.String("hmacAttack", "", "Run the challenge 31 attacker")
	var hmacAttack2 = flag.String("hmacAttack2", "", "Run the challenge 32 attacker")
	var rsaServer = flag.Bool("rsaServer", false, "Run the challenge 41 server")
	var rsaClient = flag.Bool("rsaClient", false, "Run the challenge 41 client")
	var cbcmacServer = flag.Bool("cbcmacServer", false, "Run the challenge 50 server")

	flag.Parse()

	if *crackServer {
		fmt.Println("Starting Challenge 19 crack server on port 8000")
		challenge19.CrackServer()
	} else if *hmacServer {
		fmt.Println("Starting Challenge 31 HMAC server on port 8000")
		fmt.Printf("foo: %x\n", challenge31.HmacSha1(challenge31.Secret, []byte("foo")))
		challenge31.HmacServer(50)
	} else if *hmacServer2 {
		fmt.Println("Starting Challenge 31 HMAC server on port 8000")
		fmt.Printf("foo: %x\n", challenge31.HmacSha1(challenge31.Secret, []byte("foo")))
		challenge31.HmacServer(25)
	} else if *hmacAttack != "" {
		fmt.Printf("Starting Challenge 31 HMAC attacker for filename %s\n", *hmacAttack)
		challenge31.DiscoverValidMAC(*hmacAttack, true)
	} else if *hmacAttack2 != "" {
		fmt.Printf("Starting Challenge 32 HMAC attacker for filename %s\n", *hmacAttack2)
		challenge32.DiscoverValidMAC(*hmacAttack2, true)
	} else if *rsaServer {
		fmt.Println("Starting Challenge 41 RSA server on port 8000")
		challenge41.Server()
	} else if *rsaClient {
		fmt.Println("Starting Challenge 41 RSA client with Eve listening")
		challenge41.Client([]byte("this is a test"), challenge41.Eve)
	} else if *cbcmacServer {
		fmt.Println("Starting Challenge 50 CBC MAC server on port 8000")
		challenge50.HTTPServer()
	}
}
