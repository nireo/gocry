package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/awnumar/memguard"
)

// decryptSingleFile takes in a file path and a 32-bit encryption key and undoes the encryption.
// Also removes the .gocry extension from files.
func decryptSingleFile(wg *sync.WaitGroup, path string, key []byte) error {
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

	wg.Done()

	return nil
}

// DecryptRoot takes in a starting path and a 32-bit encryption key. It decrypts all files and
// all of the subdirectories. It used to be a recursive function, but I think that filepath.Walk
// has better performance.
func DecryptRoot(startingPath string, key *memguard.Enclave) error {
	var wg sync.WaitGroup

	b, err := key.Open()
	if err != nil {
		return err
	}
	defer b.Destroy()

	if err := filepath.Walk(startingPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// This for some reason causes the problem that files are not decrypted at all
		if info.IsDir() {
			return nil
		}

		wg.Add(1)
		go decryptSingleFile(&wg, path, b.Bytes())

		return nil
	}); err != nil {
		return err
	}

	wg.Wait()

	return nil
}
