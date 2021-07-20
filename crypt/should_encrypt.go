package crypt

import "strings"

var toEncrypt = []string{}

// ShouldEncrypt takes in a filepath and checks if it should be encrypted.
func ShouldEncrypt(path string) bool {
	// if the list is empty, everything should be encrypted.
	if len(toEncrypt) == 0 {
		return false
	}

	for _, ext := range toEncrypt {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}

func SetToEncrypt(extensions []string) {
	toEncrypt = extensions
}
