package main

import (
	"fmt"
	"log"
	"net"
)

func main() {

	conn, err := net.Dial("tcp", "google.com:443")
	if err != nil {
		log.Fatal(err)
	}

	str := "Hello!"
	_, err = conn.Write([]byte(str))
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1024)
	count, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(buf[:count]))
}
