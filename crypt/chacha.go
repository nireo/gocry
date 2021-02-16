package crypt

import (
	"io/ioutil"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/exp/errors/fmt"
)

func XChachaEncrypt(key []byte, path string) error {
	// check valid lengths
	if len(key) != 32 {
		return fmt.Errorf("wrong key length. wanted=32, got=%d", len(key))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(fileData)+aead.Overhead())

	if err := ioutil.WriteFile(path+".gocry", aead.Seal(nonce, nonce, fileData, nil), 0666); err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		return err
	}

	return nil
}

func XChachaDecrypt(key []byte, path string) error {
	if len(key) != 32 {
		return fmt.Errorf("wrong key length. wanted=32, got=%d", len(key))
	}

	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	nonce, encryptedData := fileData[:aead.NonceSize()], fileData[aead.NonceSize():]
	decrypted, err := aead.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(path[:len(path)-6], decrypted, 0666); err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		return err
	}

	return nil
}
