package challenge13

import (
	"bytes"
	"crypto/rand"
	"github.com/oklog/ulid"
	"github.com/stripedpajamas/cryptopals/set1/challenge7"
	"github.com/stripedpajamas/cryptopals/set2/challenge11"
	"github.com/stripedpajamas/cryptopals/set2/challenge9"
	"net/url"
	"regexp"
	"time"
)

var key []byte = challenge11.GenerateRandomKey()

func getULID() ulid.ULID {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader)
}

func SanitizeInput(input string) string {
	re := regexp.MustCompile("[&=]")
	return re.ReplaceAllLiteralString(input, "")
}

func CreateProfile(email string) url.Values {
	uid := getULID().String()
	profile := url.Values{}
	profile.Set("email", SanitizeInput(email))
	profile.Set("uid", uid)
	profile.Set("role", "user")
	return profile
}

func queryEscape(s string) string {
	spaceCount, hexCount := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			if c == ' ' {
				spaceCount++
			}
		}
	}

	if spaceCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ':
			t[j] = '+'
			j++
		case !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9'):
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

func EncodeProfile(profile url.Values) string {
	if profile == nil {
		return ""
	}
	var buf bytes.Buffer
	keys := []string{
		"email",
		"uid",
		"role",
	}
	for _, k := range keys {
		vs := profile[k]
		prefix := queryEscape(k) + "="
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(prefix)
			buf.WriteString(queryEscape(v))
		}
	}
	return buf.String()
}

func IsAdmin(q string) bool {
	profile, err := url.ParseQuery(q)
	if err != nil {
		panic(err)
	}
	if profile.Get("role") == "admin" {
		return true
	}
	return false
}

func EncryptProfile(profile string) []byte {
	profileBytes := []byte(profile)
	padded := challenge9.Pad(profileBytes, 16)
	return challenge7.ECBEncrypter(padded, key)
}

func DecryptProfile(encrypted []byte) []byte {
	return challenge9.Unpad(challenge7.ECBDecrypter(encrypted, key), 16)
}

func ProfileCookie(email string) []byte {
	// returns a new encrypted querystring profile
	return EncryptProfile(EncodeProfile(CreateProfile(email)))
}

func AdminChecker(cookie []byte) bool {
	// returns true if the decoded cookie provided says you're an admin
	return IsAdmin(string(DecryptProfile(cookie)))
}

func CreateAdminProfile() []byte {
	// the rules: only use ProfileCookie and end up with a cookie that AdminChecker returns true for
	// step 1: assemble the pieces we need
	// - the string we will mutilate needs to have 'user'+pad in the last block
	// - - (email=) + (payload) + (&uid=26 char uid) + (&role=) [user][pad]
	// - -   6      +     5     +         31         +     6  = 48
	// - - a payload of 5 chars makes everything but 'user' fit perfectly into 16byte blocks
	// - we also need the 'admin'+pad encrypted
	// - - if 'admin' was the start of the last block, the pad would be eleven 0x11s
	// - - to get a block that has just admin and eleven 0x11s we need to append it to our payload
	// - - and make our payload take up a complete block
	// - - (email=) already takes up six, so a payload of 10 will push our appended admin payload to
	// - - its own block
	// step 2: cut and paste

	mutilationTarget := ProfileCookie("AAAAA")
	// cut off the last block, we won't need it
	mutilationTarget = mutilationTarget[:len(mutilationTarget)-16]

	paddedAdmin := append([]byte("admin"), bytes.Repeat([]byte{byte(11)}, 11)...)
	payloadBytes := append([]byte("AAAAAAAAAA"), paddedAdmin...)
	encryptedWithAdmin := ProfileCookie(string(payloadBytes))
	// grab the block that has admin + pad
	adminBlock := encryptedWithAdmin[16:32]

	// create a more perfect union
	return append(mutilationTarget, adminBlock...)
}
