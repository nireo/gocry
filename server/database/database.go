package database

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB

func GetDatabase() *gorm.DB {
	return db
}

func ConnectToDatbase() {
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
}
