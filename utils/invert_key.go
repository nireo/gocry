package main

import "github.com/awnumar/memguard"

func UseKeySecure(key *memguard.Enclave, f func([]byte) error) *memguard.Enclave {
	b, err := key.Open()
	if err != nil {
		memguard.SafePanic(err)
	}
	defer b.Destroy()

	b.Melt()

	f(b.Bytes())

	return b.Seal()
}
