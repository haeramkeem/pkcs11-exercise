package main

import (
	"fmt"
	"os"
	"log"
	"io"
)

func main() {
	f, err := os.Open("plain.txt")
	if err != nil {
		log.Fatal(err)
	}
	var buf []byte
	acc := make([]byte, 100)
	for {
		buf = make([]byte, 16)
		count, err := f.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}

		if count <16 {
			break
		}
	}
	fmt.Println(string(acc))
}
