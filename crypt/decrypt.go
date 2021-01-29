package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
	"os"
	"path/filepath"
)

// decryptSingleFile takes in a file path and a 32-bit encryption key and undoes the encryption.
// Also removes the .gocry extension from files.
func decryptSingleFile(path string, key []byte) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	// path[:len(path)-6] removes the .gocry extension from the filename -> test.png.gocry -> test.png
	if err := ioutil.WriteFile(path[:len(path)-6], plaintext, 0666); err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		return err
	}

	return nil
}

// DecryptRoot takes in a starting path and a 32-bit encryption key. It decrypts all files and
// all of the subdirectories. It used to be a recursive function, but I think that filepath.Walk
// has better performance.
func DecryptRoot(startingPath string, key []byte) error {
	if err := filepath.Walk(startingPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if err := decryptSingleFile(path, key); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
