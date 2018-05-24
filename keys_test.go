package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestNewKey(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}

	j, _ := key.MarshalJSON()
	fmt.Println(string(j))

	fmt.Println(SignKey(key, key))
}

func TestUnmarshalKey(t *testing.T) {
	_, err := UnmarshalKey(privateKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
}

var (
	privateKeyBytes = []byte(`{"kty":"EC","kid":"","crv":"P-256","alg":"ECDH-ES+A256KW","x":"iI66w2Ga0RgB6fFuQ_emzrcarynpaMTVJgxxKphn9yI","y":"WPXlPPpxdDAuU9m_MusLprM04u78es2vr5uOjDNVH0M","d":"w2CV5zI0rS4NlbnimAuMvRXtA0T_PSSaCEmNq_JPGr4"}`)
)

func TestNewSymmetricKey(t *testing.T) {
	key := NewSymmetricKey(SYMKEYALG)

	fmt.Println(hex.EncodeToString(key))
}
