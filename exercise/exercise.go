package main

import (
	"fmt"
	"log"
	"os"
	"encoding/binary"
	"encoding/base64"
	"io/ioutil"

	"github.com/miekg/pkcs11"
	"github.com/spf13/pflag"
)

const userpin = "3434"

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

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
	objList := pflag.Bool("list", false, "Print object list option : --list")

	genRsa := pflag.Bool("gen-rsa", false, "Generate rsa key : --gen-rsa --label (key label) --id (id)")
	labelName := pflag.String("label", "", "Label name : --label (key label)")
	objId := pflag.Int("id", 0, "Object Id : --id (id)")

	signRsa := pflag.Bool("sign-rsa", false, "Sign with rsa key : --sign-rsa --labal (key label) --data (filename)")
	signData := pflag.String("data", "", "Input data : --data (filename)")

	pflag.Parse()

	//------------------------------------------- Print Object List ------------------------------------------
	if *objList {
	        if err := p.FindObjectsInit(session, nil); err != nil {
	                log.Fatal(err)
	        }

	        keyObj, _, err := p.FindObjects(session, 100)
		if err != nil {
	                log.Fatal(err)
		}

	        if err = p.FindObjectsFinal(session); err != nil {
	                log.Fatal(err)
	        }

		//Attribute Template
		baseTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		}

		for i := 0; i < len(keyObj); i++ {
			attr, err := p.GetAttributeValue(session, keyObj[i], baseTemplate)
			if err != nil {
				log.Fatal(err)
			}

			if len(attr[0].Value) > 0 {
				keyType := binary.LittleEndian.Uint16(attr[3].Value)
				types := binary.LittleEndian.Uint16(attr[2].Value)

				fmt.Printf("Object ID : %d\n", attr[0].Value[0])
				fmt.Printf("    Label : %s\n", fmt.Sprintf("%s", attr[1].Value))
				fmt.Printf("     Type : %s\n", ckohex(types))
				fmt.Printf("  KeyType : %s\n", ckkhex(keyType))

				switch keyType {
					case 0x0 : //RSA
						if types == 0x02 {
							keySizeAttr, err := p.GetAttributeValue(session, keyObj[i], []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil)})
							if err != nil {
								log.Fatal(err)
							}
							fmt.Println("  KeySize :", binary.LittleEndian.Uint16(keySizeAttr[0].Value))
						}
						break
					case 0x3 : //EC
						if types == 0x02 {
							keySizeAttr, err := p.GetAttributeValue(session, keyObj[i], []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
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
						}
						break
					case 0x1f : //AES
						keySizeAttr, err := p.GetAttributeValue(session, keyObj[i], []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil)})
						if err != nil {
							log.Fatal(err)
						}
						fmt.Println("  KeySize :", binary.LittleEndian.Uint16(keySizeAttr[0].Value)*8)
						break
				}
				fmt.Println()
			}
		}
	}

	//--------------------------------------------- Generate Rsa Key -----------------------------------------------------
	if *genRsa && len(*labelName) > 0 && *objId > 0 {
		mechTemplate := []*pkcs11.Mechanism{
			pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		}

		rsaPubkeyTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *labelName),
			pkcs11.NewAttribute(pkcs11.CKA_ID, *objId),
		}

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
			pkcs11.NewAttribute(pkcs11.CKA_ID, *objId),
		}

		rsaPubkey, rsaPrivkey, err := p.GenerateKeyPair(session, mechTemplate, rsaPubkeyTemplate, rsaPrivkeyTemplate)

		if err != nil {
			log.Fatal(err)
		}

		baseTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		}

                pubAttr, err := p.GetAttributeValue(session, rsaPubkey, baseTemplate)
		if err != nil {
                        log.Fatal(err)
                }

	        fmt.Printf("Object ID : %d\n", pubAttr[0].Value[0])
	        fmt.Printf("    Label : %s\n", fmt.Sprintf("%s", pubAttr[1].Value))
	        fmt.Printf("     Type : %s\n", ckohex(binary.LittleEndian.Uint16(pubAttr[2].Value)))
	        fmt.Printf("  KeyType : %s\n", ckkhex(binary.LittleEndian.Uint16(pubAttr[3].Value)))
		pubkeySizeAttr, err := p.GetAttributeValue(session, rsaPubkey, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil)})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("  KeySize :", binary.LittleEndian.Uint16(pubkeySizeAttr[0].Value))

                privAttr, err := p.GetAttributeValue(session, rsaPrivkey, baseTemplate)
                if err != nil {
                        log.Fatal(err)
                }

                fmt.Printf("Object ID : %d\n", privAttr[0].Value[0])
                fmt.Printf("    Label : %s\n", fmt.Sprintf("%s", privAttr[1].Value))
                fmt.Printf("     Type : %s\n", ckohex(binary.LittleEndian.Uint16(privAttr[2].Value)))
                fmt.Printf("  KeyType : %s\n", ckkhex(binary.LittleEndian.Uint16(privAttr[3].Value)))
	}

	//--------------------------------------------- Sign Data w/ RSA Key -----------------------------------------------
	if *signRsa && len(*labelName) > 0 && len(*signData) > 0 {
		//Read File
		dat, err := ioutil.ReadFile(*signData)
		check(err)

		//Get Key
		privTemplate := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, *labelName),
		}
		err = p.FindObjectsInit(session, privTemplate)
		check(err)
		pvk, _, err := p.FindObjects(session, 10)
		check(err)
		err = p.FindObjectsFinal(session)
		check(err)

		//Sign Data
		if len(pvk) == 1 {
			err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, pvk[0])
			check(err)
			signed, err := p.Sign(session, dat)
			check(err)
			dst := base64.StdEncoding.EncodeToString(signed)
			fmt.Println("----- Signature -----")
			fmt.Println(dst)
		} else {
			fmt.Println("Invalid Key Label")
		}
	}
}
