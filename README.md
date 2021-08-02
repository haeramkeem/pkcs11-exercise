# Summer2021-pkcs11-practice
Clone coding of pkcs11-tool(OpenSC)  
by GoLang + github.com/miekg/pkcs11

## PKCS#11 tool flag options
### Print object list option
```
--list
```
### Generate rsa key
```
--gen-rsa --label (key label) --id (id)
```
### Label name
```
--label (key label)
```
### Object Id
```
--id (id)
```
### Sign with rsa key
```
--sign-rsa --labal (key label) --data (aign filename)
```
### Input data
```
--data (filename)
```
### Encrypt with RSA public key - only RSA_OAEP_SHA1_MGF1 supported
```
--encrypt-rsa --label (key label) --in (plain file name) --out (cipher file name)
```
### Decrypt with RSA private key
```
--decrypt-rsa --label (key label) --in (cipher file name) --out (plain file name)
```
### Generate aes key
```
--gen-aes --label (key label) --id (id)
```
### Encrypt with AES
```
--encrypt-aes --label (key label) --in (plain file name) --out (encrypt file name)
```
### Decrypt with AES
```
--decrypt-aes --label (key label) --in (encrypt file name) --out (plain file name)
```
### Input File
```
--in (filename)
```
### Output File
```
--out (filename)
```
### Generate ECDSA key
```
--gen-ec --curve (curve name) --label (key label)
```
### Types of EC curve
```
--curve (curve name)
```
### Sign with ECDSA key
```
--sign-ec --label (key label) --data (sign filename)
```
### Get RSA key
```
--getpub-rsa --label (key label) --pub
```
### Get public key of keypair
```
--pub
```
### Get private key of keypair - key must generated with unsafe flag
```
--priv
```
### Get ECDSA key
```
--getpub-ec --label (key label)
```
### Convert sign data to asn1.sequence format
```
--sign-format-openssl
```
### Verify signature by ECDSA key
```
--verify-ec --label (key label) --data (digested data) --sig (sig file)
```
### Input signature file
```
--sig (signature file)
```
### Generate rsa keypair with unsafe(exportable) priv
```
--unsafe
```
