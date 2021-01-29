package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
)

func EncryptKey(originalKey []byte) ([]byte, error) {
	res, err := http.Get("http://localhost:8080/pubkey")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("bad key data: not PEM-encoded")
	}

	if got, want := block.Type, "PUBLIC KEY"; got != want {
		log.Fatalf("unknown key type: %q, want %q", got, want)
	}

	pubkey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad public key: %s", err)
	}

	out, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, originalKey, []byte("key.txt"))
	if err != nil {
		log.Fatalf("error while encrypting key content: %s", err)
	}

	return out, nil
}
