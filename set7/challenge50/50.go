package challenge50

import (
	"io/ioutil"
	"net/http"

	"github.com/stripedpajamas/cryptopals/set2/challenge9"
	"github.com/stripedpajamas/cryptopals/set7/challenge49"
)

func ForgeScript(key []byte) []byte {
	// the idea i have here is that i'm going to write a script of my own,
	// then i'm going to add a comment // on the end, and then concat their script
	// to my own. their script generates a specific hash, my script generates a specific
	// hash. should be nearly the same process as 49 part 2. xor my own MAC with the
	// 1st block of their script, then concat everything together
	theirScript := challenge9.Pad([]byte("alert('MZA who was that?');\n"), 16)
	myScript := challenge9.Pad([]byte("alert('Ayo, the Wu is back!');\n\n//"), 16)
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	myTag := challenge49.CBCMAC(myScript, iv, key)

	// now xor my tag with the first block of their message
	bridgeBlock := make([]byte, 16)
	copy(bridgeBlock, theirScript[:16])
	for idx, b := range myTag {
		bridgeBlock[idx] = bridgeBlock[idx] ^ b
	}

	myScript = append(myScript, bridgeBlock...)
	myScript = append(myScript, theirScript[16:]...)

	return myScript
}

func HTTPServer() {
	// first write our wacky javascript to a file, then serve up index.html
	// and provide a route to our wacky javascript
	script := challenge9.Unpad(ForgeScript([]byte("YELLOW SUBMARINE")), 16)
	ioutil.WriteFile("/tmp/wackyscript.js", script, 0644)
	http.HandleFunc("/script", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "/tmp/wackyscript.js")
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "set7/challenge50/index.html")
	})
	http.ListenAndServe(":8000", nil)
}
