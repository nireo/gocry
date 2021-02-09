package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("you need to provide user's id")
	}

	file, err := ioutil.ReadFile("./to_decrypt")
	if err != nil {
		log.Fatal(err)
	}

	pemd, err := ioutil.ReadFile("private.pem")
	if err != nil {
		log.Fatalf("error decoding key data, err: %s", err)
	}

	block, _ := pem.Decode(pemd)
	if block == nil {
		log.Fatalf("error decoding key data, err: %s", err)
	}

	if got, want := block.Type, "PRIVATE KEY"; got != want {
		log.Fatalf("wrong key type. got=%s, want=%s", got, want)
	}

	// Decode the RSA private key
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad private key, err: %s", err)
	}

	out, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, file, []byte("key-"+os.Args[1]))
	if err != nil {
		log.Fatalf("error decrypting key, err: %s", err)
	}

	if err := ioutil.WriteFile("./key.txt", out, 0666); err != nil {
		log.Fatalf("error writing key data, err: %s", err)
	}
}
