package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func DecryptRSA(labelUUID string, key []byte) ([]byte, error) {
	pemd, err := ioutil.ReadFile("../private.pem")
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemd)
	if block == nil {
		return nil, errors.New("pem decode block was nil")
	}

	if got, want := block.Type, "PRIVATE KEY"; got != want {
		return nil, fmt.Errorf("wrong key type. got=%s, want=%s", got, want)
	}

	// Decode the RSA private key
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	out, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, key, []byte("key-"+labelUUID))
	if err != nil {
		return nil, err
	}

	return out, nil
}
