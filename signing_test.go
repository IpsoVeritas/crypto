package crypto

import (
	"fmt"
	"testing"
)

func TestNewSigner(t *testing.T) {
	key, _ := NewKey()
	_, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigner_Sign(t *testing.T) {
	key, _ := NewKey()
	s, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := s.Sign([]byte("some test string"))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(signed.FullSerialize())
}

func TestSignCompact(t *testing.T) {
	key, _ := NewKey()
	key.KeyID = "abc"
	s, _ := NewSigner(key)
	signed, _ := s.Sign([]byte("stuff"))

	m, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Compact message:", m)
}
