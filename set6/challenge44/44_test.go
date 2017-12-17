package challenge44

import (
	"math/big"

	"crypto/sha1"
	"fmt"
	"testing"

	"github.com/stripedpajamas/cryptopals/set6/challenge43"
)

var msgs = [][]byte{
	[]byte("Listen for me, you better listen for me now. "),
	[]byte("Listen for me, you better listen for me now. "),
	[]byte("When me rockin' the microphone me rock on steady, "),
	[]byte("Yes a Daddy me Snow me are de article dan. "),
	[]byte("But in a in an' a out de dance em "),
	[]byte("Aye say where you come from a, "),
	[]byte("People em say ya come from Jamaica, "),
	[]byte("But me born an' raised in the ghetto that I want yas to know, "),
	[]byte("Pure black people mon is all I mon know. "),
	[]byte("Yeah me shoes a an tear up an' now me toes is a show a "),
	[]byte("Where me a born in are de one Toronto, so "),
}

// [r, s]
var sigStrings = [][]string{
	{
		"1105520928110492191417703162650245113664610474875",
		"1267396447369736888040262262183731677867615804316",
	},
	{
		"51241962016175933742870323080382366896234169532",
		"29097472083055673620219739525237952924429516683",
	},
	{
		"228998983350752111397582948403934722619745721541",
		"277954141006005142760672187124679727147013405915",
	},
	{
		"1099349585689717635654222811555852075108857446485",
		"1013310051748123261520038320957902085950122277350",
	},
	{
		"425320991325990345751346113277224109611205133736",
		"203941148183364719753516612269608665183595279549",
	},
	{
		"486260321619055468276539425880393574698069264007",
		"502033987625712840101435170279955665681605114553",
	},
	{
		"537050122560927032962561247064393639163940220795",
		"1133410958677785175751131958546453870649059955513",
	},
	{
		"826843595826780327326695197394862356805575316699",
		"559339368782867010304266546527989050544914568162",
	},
	{
		"1105520928110492191417703162650245113664610474875",
		"1021643638653719618255840562522049391608552714967",
	},
	{
		"51241962016175933742870323080382366896234169532",
		"506591325247687166499867321330657300306462367256",
	},
	{
		"228998983350752111397582948403934722619745721541",
		"458429062067186207052865988429747640462282138703",
	},
}

var sigs []challenge43.MessageSignature

var publicKey *big.Int

func init() {
	sigs = make([]challenge43.MessageSignature, len(sigStrings))
	for i, str := range sigStrings {
		r, okr := new(big.Int).SetString(str[0], 10)
		s, oks := new(big.Int).SetString(str[1], 10)
		if !okr || !oks {
			panic("Could not convert number to big int")
		}
		sigs[i] = challenge43.MessageSignature{
			R: r,
			S: s,
		}
	}
	y, ok := new(big.Int).SetString("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)
	if !ok {
		panic("Public key failed to convert to big int")
	}
	publicKey = y
}

func TestRecoverK(t *testing.T) {
	dsa := challenge43.DSA{}
	dsa.Initialize()

	recoveredPrivateKey := RecoverK(&dsa, msgs, sigs)

	// if we got the right key, we should be able to sign something with it
	// and verify with the provided public key
	myMessage := []byte("hello world")
	myHash := sha1.Sum(myMessage)
	mySig := dsa.Sign(myHash[:], recoveredPrivateKey)
	if !dsa.Verify(myHash[:], mySig, publicKey) {
		fmt.Println("Signed message did not verify")
		t.Fail()
	}
}
