package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
	"log"
	"os"
)

func decryptSingleFile(path string, key []byte) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err.Error())
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err.Error())
	}

	// path[:len(path)-6] removes the .gocry extension from the filename -> test.png.gocry -> test.png
	if err := ioutil.WriteFile(path[:len(path)-6], plaintext, 0666); err != nil {
		log.Fatal(err)
	}

	if err := os.Remove(path); err != nil {
		log.Fatal(err)
	}
}

// This function is used recursively to encrypt all the subdirectories, and the files
// in those directores
func encryptDirectory(path string, key []byte) {
	files, err := ioutil.ReadDir(os.Getenv("rootDir"))
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.IsDir() {
			encryptDirectory(path+"/"+f.Name(), key)
		} else {
			encryptSingleFile(path+"/"+f.Name(), key)
		}
	}
}

func main() {
	key, err := ioutil.ReadFile(os.Getenv("rootDir") + "/key.txt")
	if err != nil {
		log.Fatal(err)
	}

	if len(key) != 32 {
		log.Fatal("The key provided has the wrong length, wanted 32 got: ", len(key))
	}

	decryptDirectory(os.Getenv("rootDir"), key)
}
