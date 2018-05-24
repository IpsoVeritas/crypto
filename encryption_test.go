package crypto

import (
	"fmt"
	"math/rand"
	"testing"

	"gopkg.in/square/go-jose.v1"
)

var (
	IPFSSTRING = []byte("/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")
)

func TestEncrypter_Encrypt_Multi(t *testing.T) {
	// initialize encrypter
	enc, err := NewEncrypter()
	if err != nil {
		t.Error(err)
	}

	// initialize keys and add them as recipients
	var keys [3]*jose.JsonWebKey
	for i := 0; i < 3; i++ {
		keys[i], err = NewKey()
		if err != nil {
			t.Fatal(err)
		}
		jp, _ := keys[i].MarshalJSON()
		fmt.Println(string(jp))
		pk, err := NewPublicKey(keys[i])
		if err != nil {
			t.Fatal(err)
		}
		j, _ := pk.MarshalJSON()
		fmt.Println(string(j))

		err = enc.AddRecipient(pk)
		if err != nil {
			t.Fatal(err)
		}
	}

	// encrypt message
	msg, err := enc.Encrypt(IPFSSTRING)
	if err != nil {
		panic(err)
	}

	fmt.Println(msg.FullSerialize())

	// select random recipient key and try to decrypt
	k := keys[rand.Intn(3)]
	_, _, m, err := msg.DecryptMulti(k)
	if err != nil {
		t.Fatal(err)
	}

	if string(m) != string(IPFSSTRING) {
		t.Errorf("Decrypted message not the same as input message: %s != %s", string(m), string(IPFSSTRING))
	}
}

func TestSymetricEncrypter_Encrypt(t *testing.T) {

	// create random symetric key
	symkey := NewSymmetricKey(SYMKEYALG)

	// initialize encrypter with key
	s, err := NewSymmetricEncrypter(symkey)
	if err != nil {
		panic(err)
	}

	// encrypt message
	smsg, err := s.Encrypt(IPFSSTRING)
	if err != nil {
		panic(err)
	}

	// decrypt message
	sdecrypted, err := smsg.Decrypt(symkey)

	if string(sdecrypted) != string(IPFSSTRING) {
		t.Errorf("Decrypted message not the same as input message: %s != %s", string(sdecrypted), string(IPFSSTRING))
	}
}

func TestSymetricEncrypter_EncryptCompact(t *testing.T) {

	// create random symetric key
	symkey := NewSymmetricKey(SYMKEYALG)

	// initialize encrypter with key
	s, err := NewSymmetricEncrypter(symkey)
	if err != nil {
		panic(err)
	}

	// encrypt message
	smsg, err := s.Encrypt(IPFSSTRING)
	if err != nil {
		panic(err)
	}

	m, err := smsg.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Compact format encrypted string:", m)
}
