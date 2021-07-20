package crypt

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/awnumar/memguard"
)

type EncryptionScheme string
type CryptFunc func(*sync.WaitGroup, string, []byte) error

const (
	AES256  EncryptionScheme = "aes-gcm256"
	XCHACHA EncryptionScheme = "xchacha20poly1305"
)

// Encryptor struct holds all the functions and logic for encryption.
type Encryptor struct {
	encryptionScheme EncryptionScheme
	wantedExtensions []string
	key              *memguard.Enclave
	rootDir          string
	wg               *sync.WaitGroup
}

func (enc *Encryptor) NewWithScheme(dir string, scheme EncryptionScheme,
	key *memguard.Enclave, toEncrypt []string) *Encryptor {

	return &Encryptor{
		encryptionScheme: scheme,
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

func (enc *Encryptor) encMain() {
	switch enc.encryptionScheme {
	case AES256:
		enc.encryptPath(aesgcmEncrypt)
	case XCHACHA:
		enc.encryptPath(XChachaEncrypt)
	}
}

func (enc *Encryptor) encryptPath(fn CryptFunc) error {
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
			go fn(enc.wg, path, b.Bytes())
		}
		return nil
	}); err != nil {
		return err
	}

	enc.wg.Wait()
	return nil
}

// EncryptRootWithScheme takes in an optional encryption scheme and then proceeds
// to encrypt the root directory using that scheme.
func EncryptRootWithScheme(rootDir string, scheme EncryptionScheme, key *memguard.Enclave) error {
	switch scheme {
	case AES256:
		EncryptCommon(aesgcmEncrypt, rootDir, key)
	case XCHACHA:
		EncryptCommon(XChachaEncrypt, rootDir, key)
	}

	return nil
}

// DecryptRootWithScheme takes in a optional decryption scheme and then proceeds
// to decrypt the root directory using that scheme.
func DecryptRootWithScheme(rootDir string, scheme EncryptionScheme, key *memguard.Enclave) error {
	switch scheme {
	case AES256:
		DecryptCommon(aesgcmEncrypt, rootDir, key)
	case XCHACHA:
		DecryptCommon(XChachaDecrypt, rootDir, key)
	}
	return nil
}

// EncryptCommon goes through all the files in a root directory and executes the given CryptFunc
// on each file.
func EncryptCommon(fn CryptFunc, rootDir string, key *memguard.Enclave) error {
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
			go fn(&wg, path, b.Bytes())
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
func DecryptCommon(fn CryptFunc, rootDir string, key *memguard.Enclave) error {
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
		go fn(&wg, path, b.Bytes())
		return nil
	}); err != nil {
		return err
	}

	wg.Wait()
	return nil
}
