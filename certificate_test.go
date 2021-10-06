package crypto

import (
	"testing"
	"time"

	"github.com/IpsoVeritas/document"
)

func Test_CreateCertificate(t *testing.T) {
	issuer, _ := NewKey()
	subject, _ := NewKey()

	_, err := CreateCertificate(issuer, subject, 0, []string{"*"}, 3600, "")
	if err != nil {
		t.Fatal(err)
	}
}

func Test_VerifyCertificate(t *testing.T) {
	issuer, _ := NewKey()
	subject, _ := NewKey()

	cert, err := CreateCertificate(issuer, subject, 0, []string{"*"}, 3600, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyCertificate(cert, 1)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_VerifyCertificate_Expired(t *testing.T) {
	issuer, _ := NewKey()
	subject, _ := NewKey()

	cert, err := CreateCertificate(issuer, subject, 0, []string{"*"}, 1, "")
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second * 2)

	_, err = VerifyCertificate(cert, 1)
	if err == nil {
		t.Fatal("Certificate should have been expired")
	}
}

func Test_VerifyCertificate_WrongKeyLevel(t *testing.T) {
	issuer, _ := NewKey()
	subject, _ := NewKey()

	cert, err := CreateCertificate(issuer, subject, 100, []string{"*"}, 3600, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyCertificate(cert, 1)
	if err == nil {
		t.Fatal("Verification should have failed")
	}
}

func Test_VerifyCertificate_SameKeyLevel(t *testing.T) {
	issuer, _ := NewKey()
	subject, _ := NewKey()

	cert, err := CreateCertificate(issuer, subject, 100, []string{"*"}, 3600, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyCertificate(cert, 100)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_VerifyDocumentWithCertificateChain_WrongDocType(t *testing.T) {
	issuer, _ := NewKey()
	// issuerPK, _ := NewPublicKey(issuer)
	subject, _ := NewKey()
	subPK, _ := NewPublicKey(subject)

	cert, err := CreateCertificate(issuer, subPK, 100, []string{"test"}, 3600, "")
	if err != nil {
		t.Fatal(err)
	}

	doc := document.NewBase()
	doc.Certificate = cert
	_, _, _, err = VerifyDocumentWithCertificateChain(doc, 100)
	if err == nil {
		t.Fatal("Should not be allowed")
	}
}

func Test_VerifyDocumentWithCertificateChain_LongChain(t *testing.T) {
	issuer, _ := NewKey()
	// issuerPK, _ := NewPublicKey(issuer)

	prevCert := ""
	iss := issuer
	var err error
	docTypes := []string{"https://IpsoVeritas.github.io/schemas/v0/base.json", "https://IpsoVeritas.github.io/schemas/v0/certificate.json"}
	for i := 100; i < 110; i++ {
		subject, _ := NewKey()
		subPK, _ := NewPublicKey(subject)

		if i == 109 {
			docTypes = []string{"https://IpsoVeritas.github.io/schemas/v0/base.json"}
		}
		cert, err := CreateCertificate(iss, subPK, i, docTypes, 3600, prevCert)
		if err != nil {
			t.Fatal(err)
		}
		iss = subject
		prevCert = cert
	}

	doc := document.NewBase()
	doc.Certificate = prevCert
	allowed, _, _, err := VerifyDocumentWithCertificateChain(doc, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("Should have been allowed")
	}
}

func Test_VerifyDocumentWithCertificateChain_DocTypeSubset(t *testing.T) {
	issuer, _ := NewKey()
	// issuerPK, _ := NewPublicKey(issuer)

	prevCert := ""
	iss := issuer
	var err error
	docTypes := []string{"https://IpsoVeritas.github.io/schemas/v0/base.json", "https://IpsoVeritas.github.io/schemas/v0/certificate.json"}
	for i := 100; i < 102; i++ {
		subject, _ := NewKey()
		subPK, _ := NewPublicKey(subject)

		if i == 101 {
			docTypes = []string{"https://IpsoVeritas.github.io/schemas/v0/base.json"}
		}
		cert, err := CreateCertificate(iss, subPK, i, docTypes, 3600, prevCert)
		if err != nil {
			t.Fatal(err)
		}
		iss = subject
		prevCert = cert
	}

	doc := document.NewBase()
	doc.Certificate = prevCert
	allowed, _, _, err := VerifyDocumentWithCertificateChain(doc, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("Should have been allowed")
	}
}

func Test_VerifyDocumentWithCertificateChain_DocTypeSubset_Fail(t *testing.T) {
	issuer, _ := NewKey()
	// issuerPK, _ := NewPublicKey(issuer)

	prevCert := ""
	iss := issuer
	var err error
	docTypes := []string{"certificate"}
	for i := 100; i < 102; i++ {
		subject, _ := NewKey()
		subPK, _ := NewPublicKey(subject)

		if i == 101 {
			docTypes = []string{"base"}
		}
		cert, err := CreateCertificate(iss, subPK, i, docTypes, 3600, prevCert)
		if err != nil {
			t.Fatal(err)
		}
		iss = subject
		prevCert = cert
	}

	doc := document.NewBase()
	doc.Certificate = prevCert
	allowed, _, _, err := VerifyDocumentWithCertificateChain(doc, 1000)
	if err == nil {
		t.Fatal("Should not have been allowed")
	}
	if allowed {
		t.Fatal("Should not have been allowed")
	}
}
