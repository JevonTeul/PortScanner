// Filename: main.go
package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
)

func main() {
	// define the target host and port we want to connect to
	target := "scanme.nmap.org"
	port := 80
	portStr := strconv.Itoa(port)
	address := net.JoinHostPort(target, portStr)
	dialer := net.Dialer{
		Timeout: 5 * time.Second,
	}
	// attempt to establish a connection
	// the Dial function is used to connect to a server
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		log.Fatalf("Unable to connect to %s: %v", address, err)
	}
	defer conn.Close()

	fmt.Printf("Connection to %s was successful\n", address)
}
