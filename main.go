package main

import "log"

func main() {
	targets, err := ScanNetwork("en0", 1)
	if err != nil {
		log.Fatal(err)
	}

	CreateTable(targets)
}
