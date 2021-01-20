package main

// CODE FROM: https://gist.github.com/sdorra/1c95de8cb80da31610d2ad767cd6f251 (slightly modified)

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"os"
)

func main() {
	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		panic(err)
	}

	publicKey := key.PublicKey

	saveGobKey("private.key", key)
	savePEMKey("private.pem", key)

	saveGobKey("public.key", publicKey)
	savePublicPEMKey("public.pem", publicKey)
}

func saveGobKey(fileName string, key interface{}) {
	outFile, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	encoder := gob.NewEncoder(outFile)
	if err := encoder.Encode(key); err != nil {
		panic(err)
	}
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if err := pem.Encode(outFile, privateKey); err != nil {
		panic(err)
	}
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		panic(err)
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer pemfile.Close()

	if err := pem.Encode(pemfile, pemkey); err != nil {
		panic(err)
	}
}
