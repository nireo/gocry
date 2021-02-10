package utils

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/awnumar/memguard"
	"github.com/nireo/gocry/crypt"
)

func EncryptionKeyToServer(key *memguard.Enclave, uuid string) error {
	b, err := key.Open()
	if err != nil {
		return fmt.Errorf("error opening memguard enclave, err: %s", err)
	}
	defer b.Destroy()

	encryptedRSAKey, err := crypt.EncryptKey(b.Bytes(), uuid)
	if err != nil {
		return fmt.Errorf("error when creating RSA key, err: %s", err)
	}

	req, err := http.NewRequest("POST", "http://localhost:8080/enc_key?id="+uuid,
		bytes.NewBuffer(encryptedRSAKey))
	if err != nil {
		return fmt.Errorf("error creating request, err: %s", err)
	}

	cl := http.Client{}
	res, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("error running request, err: %s", err)
	}

	// check that the request is successful
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("request was unsuccessful, wrong status code. got=%d, want=%d",
			res.StatusCode, http.StatusOK)
	}

	return nil
}
