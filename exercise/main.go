package main

import (
	"fmt"
	"log"
	"os"

	"github.com/miekg/pkcs11"
)

func main() {
	libPath := os.Getenv("LIB")
	fmt.Println("using pkcs11 library", libPath)

	p := pkcs11.New(libPath)
	if p == nil {
		log.Fatalf("cannot load %s", libPath)
	}

	if err := p.Initialize(); err != nil {
		log.Fatal(err)
	}

	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("slots:", slots)
	fmt.Printf("slots[0]: 0x%x\n", slots[0])
}
