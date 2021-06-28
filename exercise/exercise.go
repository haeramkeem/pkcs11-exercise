package main

import (
	"fmt"
	"log"
	"os"
	"encoding/binary"
	"bytes"

	"github.com/miekg/pkcs11"
	"github.com/spf13/pflag"
)

const userpin = "3434"

func ckohex(attrV uint16) string {
	switch attrV {
		case 0x2 :
			return "pubkey"
		case 0x3 :
			return "prikey"
		case 0x4 :
			return "seckey"
		default :
			return "idonno"
	}
}

func ckkhex(attrV uint16) string {
	switch attrV {
		case 0x0 :
			return "rsa"
		case 0x3 :
			return "ec"
		case 0x1f :
			return "aes"
		default :
			return "idonno"
	}
}

func main() {
	libPath := os.Getenv("LIB")

	p := pkcs11.New(libPath)
	if p == nil {
		log.Fatalf("cannot load %s", libPath)
	}

	if err := p.Initialize(); err != nil {
		log.Fatal(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Fatal(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatal(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, userpin)
	if err != nil {
		log.Fatal(err)
	}
	defer p.Logout(session)

	info, err := p.GetInfo()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Module :", libPath)
	fmt.Printf("Slot : 0x%x\n", slots[0])
	fmt.Println("Login Session :", session, userpin)
	fmt.Println("Info :", info)
	fmt.Println()

	//Print object option
	objList := pflag.Bool("list", false, "Print object list option")

	genRsa := pflag.Bool("gen-rsa", false, "Generate rsa key")
	labelName := pflag.String("label", "", "Label name")
	objId := pflag.Uint16("id", 0, "Object Id")

	pflag.Parse()

	if *objList {

	//Search Pubkey
	pubkeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	if err := p.FindObjectsInit(session, pubkeyTemplate); err != nil {
		log.Fatal(err)
	}

	pubkeyObj, _, err := p.FindObjects(session, 100)
	if err != nil {
		log.Fatal(err)
	}

	if err = p.FindObjectsFinal(session); err != nil {
		log.Fatal(err)
	}

	//Search Seckey
        seckeyTemplate := []*pkcs11.Attribute{
                pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
        }

        if err := p.FindObjectsInit(session, seckeyTemplate); err != nil {
                log.Fatal(err)
        }

        seckeyObj, _, err := p.FindObjects(session, 10)
        if err != nil {
                log.Fatal(err)
        }

        if err = p.FindObjectsFinal(session); err != nil {
                log.Fatal(err)
        }

	pubkeyObj = append(pubkeyObj, seckeyObj...)

	//Attribute Template
	baseTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	}

	for i := 0; i < len(pubkeyObj); i++ {
		attr, err := p.GetAttributeValue(session, pubkeyObj[i], baseTemplate)
		if err != nil {
			log.Fatal(err)
		}

		keyType := binary.LittleEndian.Uint16(attr[3].Value)

		fmt.Printf("Object ID : %d\n", attr[0].Value[0])
		fmt.Printf("    Label : %s\n", fmt.Sprintf("%s", attr[1].Value))
		fmt.Printf("     Type : %s\n", ckohex(binary.LittleEndian.Uint16(attr[2].Value)))
		fmt.Printf("  KeyType : %s\n", ckkhex(keyType))

		switch keyType {
			case 0x0 : //RSA
				keySizeTemplate := []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
				}
				keySizeAttr, err := p.GetAttributeValue(session, pubkeyObj[i], keySizeTemplate)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("  KeySize :", binary.LittleEndian.Uint16(keySizeAttr[0].Value))
				break
			case 0x3 : //EC
				keySizeTemplate := []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
				}
				keySizeAttr, err := p.GetAttributeValue(session, pubkeyObj[i], keySizeTemplate)
				if err != nil {
					log.Fatal(err)
				}
				var ksize int
				size := len(keySizeAttr[0].Value)
				if (size - 2) <= 127 {
					ksize = (size - 3) * 4
				} else if (size - 3) <= 255 {
					ksize = (size - 4) * 4
				} else {
					ksize = (size - 5) * 4
				}
				fmt.Println("  KeySize :", ksize)
				break
			case 0x1f : //AES
				keySizeTemplate := []*pkcs11.Attribute{
					pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
				}
				keySizeAttr, err := p.GetAttributeValue(session, pubkeyObj[i], keySizeTemplate)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("  KeySize :", binary.LittleEndian.Uint16(keySizeAttr[0].Value)*8)
				break
		}
		fmt.Println()
	}
}
	if *genRsa && len(*labelName) > 0 && *objId > 0 {
		buf := new(bytes.Buffer)
		var num uint16 = *objId
		err := binary.Write(buf, binary.LittleEndian, num)
		if err != nil {
			log.Fatal(err)
		}
		id := buf.Bytes()

		buf = new(bytes.Buffer)
		num = 2048
		err = binary.Write(buf, binary.LittleEndian, num)
		if err != nil {
			log.Fatal(err)
		}
		ksize := buf.Bytes()

		buf = new(bytes.Buffer)
		var exp uint32 = 65537
		err = binary.Write(buf, binary.LittleEndian, exp)
		if err != nil {
			log.Fatal(err)
		}
		expo := buf.Bytes()

		fmt.Println("1")
		rsaPubkeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, ksize),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, expo),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *labelName),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}

		fmt.Println("2")

		rsaPrivkeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *labelName),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		}

		fmt.Println("3")

		rsaPubkey, err := p.CreateObject(session, rsaPubkeyTemplate)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("4")

		rsaPrivkey, err := p.CreateObject(session, rsaPrivkeyTemplate)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("5")

		baseTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
		}

		fmt.Println("6")

                pubAttr, err := p.GetAttributeValue(session, rsaPubkey, baseTemplate)
		if err != nil {
                        log.Fatal(err)
                }

	        fmt.Printf("Object ID : %d\n", pubAttr[0].Value[0])
	        fmt.Printf("    Label : %s\n", fmt.Sprintf("%s", pubAttr[1].Value))
	        fmt.Printf("     Type : %s\n", ckohex(binary.LittleEndian.Uint16(pubAttr[2].Value)))
	        fmt.Printf("  KeyType : %s\n", ckkhex(binary.LittleEndian.Uint16(pubAttr[3].Value)))
		fmt.Println("  KeySize :", binary.LittleEndian.Uint16(pubAttr[4].Value))

                privAttr, err := p.GetAttributeValue(session, rsaPrivkey, baseTemplate)
                if err != nil {
                        log.Fatal(err)
                }

                fmt.Printf("Object ID : %d\n", privAttr[0].Value[0])
                fmt.Printf("    Label : %s\n", fmt.Sprintf("%s", privAttr[1].Value))
                fmt.Printf("     Type : %s\n", ckohex(binary.LittleEndian.Uint16(privAttr[2].Value)))
                fmt.Printf("  KeyType : %s\n", ckkhex(binary.LittleEndian.Uint16(privAttr[3].Value)))
                fmt.Println("  KeySize :", binary.LittleEndian.Uint16(privAttr[4].Value))
	}
}
