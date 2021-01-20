package utils

import "crypto/rand"

// Gen32BitKey creates a random 32 bit key for AES encryption. Using the crypto standard library.
func Gen32BitKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}
