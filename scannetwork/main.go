package main

import (
	"log"
	"time"

	"github.com/stefanwichmann/lanscan"
)

func main() {
	// Scan for hosts listening on tcp port 80.
	// Use 20 threads and timeout after 5 seconds.
	hosts, err := lanscan.ScanLinkLocal("tcp4", 80, 20, 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	for _, host := range hosts {
		log.Printf("Host %v responded.", host)
	}
}
