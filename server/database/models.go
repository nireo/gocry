package database

import "gorm.io/gorm"

// Victim database model
type Victim struct {
	gorm.Model
	UUID          string `json:"uuid"` // A unique id used to identify the victim
	IP            string `json:"ip"`
	Timestamp     int64  `json:"timestamp"` // A timestamp of the infection
	Completed     bool   `json:"completed"` // A indicator if the transaction has been payed
	DueDate       int64  `json:"due_date"`  // timestamp but with available time added
	EncryptionKey []byte
}
