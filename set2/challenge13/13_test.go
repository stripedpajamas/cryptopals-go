package challenge13

import (
	"net/url"
	"testing"
)

func TestIsAdmin(t *testing.T) {
	encodedProfile := EncodeProfile(CreateProfile("bing@crosby.net"))
	if IsAdmin(encodedProfile) != false {
		t.Fail()
	}
}

func TestCreateProfile(t *testing.T) {
	profile := CreateProfile("bing@crosby.net")
	if profile.Get("email") != "bing@crosby.net" {
		t.Fail()
	}
	if profile.Get("role") != "user" {
		t.Fail()
	}
	if len(profile.Get("uid")) != 26 {
		t.Fail()
	}
}

func TestEncodeProfile(t *testing.T) {
	profile := CreateProfile("bing@crosby.net")
	encodedProfile := EncodeProfile(profile)
	parsedProfile, err := url.ParseQuery(encodedProfile)
	if err != nil {
		panic(err)
	}
	for k, v := range parsedProfile {
		if v[0] != profile.Get(k) {
			t.Fail()
		}
	}
}

func TestSanitizeInput(t *testing.T) {
	sneakyProfile := CreateProfile("foo@bar.com&role=admin")
	if sneakyProfile.Get("email") != "foo@bar.comroleadmin" {
		t.Fail()
	}
}

func TestEncryptProfile(t *testing.T) {
	encryptedProfile := EncryptProfile(EncodeProfile(CreateProfile("foo@bar.com")))
	encLen := len(encryptedProfile)
	// we can't make many assertions about the encrypted data except that it decrypts
	// and we know the length that it should be

	if encLen != 64 {
		t.Fail()
	}

	decrypted := DecryptProfile(encryptedProfile)
	parsed, err := url.ParseQuery(string(decrypted))
	if err != nil {
		panic(err)
	}

	if parsed.Get("email") != "foo@bar.com" {
		t.Fail()
	}
	if parsed.Get("role") != "user" {
		t.Fail()
	}
}

func TestDecryptProfile(t *testing.T) {
	encrypted := EncryptProfile(EncodeProfile(CreateProfile("foo@bar.com")))
	decrypted := DecryptProfile(encrypted)
	parsed, err := url.ParseQuery(string(decrypted))
	if err != nil {
		panic(err)
	}

	if parsed.Get("email") != "foo@bar.com" {
		t.Fail()
	}
	if parsed.Get("role") != "user" {
		t.Fail()
	}
}

func TestProfileCookie(t *testing.T) {
	profile := ProfileCookie("foo@bar.com")

	decoded, err := url.ParseQuery(string(DecryptProfile(profile)))
	if err != nil {
		t.Fail()
	}

	if decoded.Get("email") != "foo@bar.com" {
		t.Fail()
	}
}

func TestAdminChecker(t *testing.T) {
	profile := ProfileCookie("foo@bar.com")
	isAdmin := AdminChecker(profile)

	if isAdmin != false {
		t.Fail()
	}

	// also test with a sneaky one
	profile = ProfileCookie("foo@bar.com&role=admin")
	isAdmin = AdminChecker(profile)

	if isAdmin != false {
		t.Fail()
	}
}

func TestCreateAdminProfile(t *testing.T) {
	// https://cryptopals.com/sets/2/challenges/13
	adminProfile := CreateAdminProfile()

	if AdminChecker(adminProfile) != true {
		t.Fail()
	}
}
