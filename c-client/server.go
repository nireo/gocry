package main

import (
	"log"
	"net"

	uuid "github.com/satori/go.uuid"
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatalf("error creating listener, err: %s", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("error accepting request, err: %s", err)
		}

		go handleNewConnection(conn)
	}
}

func handleNewConnection(conn net.Conn) {
	buffer := make([]byte, 1024)

	for {
		length, err := conn.Read(buffer)
		if err != nil {
			// stop handleling connection
			return
		}
		action := string(buffer[:length])

		if action == "uuid" {
			conn.Write([]byte(generateUUID()))
		}
	}

}

func generateUUID() string {
	newUuid, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("error creating uuid")
	}

	return newUuid.String()
}
