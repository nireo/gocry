package gen_rsa

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

func GenerateRSAKeypair() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	if err := saveGobKey("private.key", key); err != nil {
		return err
	}
	if err := savePEMKey("private.pem", key); err != nil {
		return err
	}
	if err := saveGobKey("public.key", key.PublicKey); err != nil {
		return err
	}
	if err := savePublicPEMKey("public.pem", key.PublicKey); err != nil {
		return err
	}

	return nil
}

func saveGobKey(fileName string, key interface{}) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	encoder := gob.NewEncoder(outFile)
	if err := encoder.Encode(key); err != nil {
		return err
	}
	return nil
}

func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if err := pem.Encode(outFile, privateKey); err != nil {
		return err
	}

	return nil
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) error {
	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return err
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer pemfile.Close()

	if err := pem.Encode(pemfile, pemkey); err != nil {
		return err
	}

	return nil
}
