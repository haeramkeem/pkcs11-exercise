package main

import (
	"fmt"
	"encoding/binary"
)

func main() {
	exp := []byte{0x01, 0x00, 0x01, 0x00}
	fmt.Println(binary.LittleEndian.Uint32(exp))
}
