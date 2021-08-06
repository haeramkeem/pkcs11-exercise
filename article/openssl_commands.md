# OpenSSL 실습
#개인공부/암호학
## RSA
### 랜덤한 2048비트 RSA키를 만들어 파일로 저장해주는 명령어
```
openssl genrsa -out 파일이름.pem 2048
```

### 키가 개인키인지 확인
```
openssl rsa -in 개인키.pem -text -noout
```

### 개인키로부터 공개키 계산해 저장
```
openssl rsa -in 개인키.pem -out 공개키.pem -outform PEM -pubout
```

### RSA-OAEP-SHA1-MGF1으로 암호화된 파일 복호화하기
#### Base64 디코딩
```
openssl base64 -d -in 입력 -out 출력
```
#### 복호화
```
openssl pkeyutl -decrypt -inkey 개인키 -in 암호파일 -out 결과파일 -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1
```

### 올바른 전자서명 찾기
#### Hex to binary 인코딩
```
xxd -r -p hex파일 바이너리
```
#### 검증
```
openssl pkeyutl -verify -pubin -inkey 공개키 -pkeyopt rsa_padding_mode:pss -pkeyopt digest:sha256 -in 바이너리메시지 -sigfile 바이너리서명
```

## -> 결과
- - - -
## AES
### 랜덤한 32바이트 키 만들기
```
openssl rand -base64 -out 파일이름.pem 32
```

### AES-256-CBC로 암호화된 파일 복호화
```
openssl aes-256-cbc -nosalt -d -in 암호문.bin -out 결과파일 -K 키 -iv IV값
```
- - - -
## ECDSA
### ECDSA secp256r1 키 생성
```
openssl ecparam -genkey -outform PEM -out 키.pem -name prime256v1
```
### 개인키 - 공개키 전환
```
openssl ec -in 개인키.pem -pubout -outform PEM -out 공개키.pem
```
### 개인키로 커브 알아내기(EC 키 정보 확인)
```
openssl ec -in 개인키.pem -text -noout
```
### 올바른 전자서명 찾기
#### sha256으로 digest하기
```
openssl dgst -sha256 -binary 원본.txt > 다이제스트.bin
```
#### ECDSA with SHA256 검증하기
```
openssl pkeyutl -verify -in 다이제스트.bin -sigfile 서명.bin -pubin -inkey 공개키.pem -pkeyopt digest:sha256
```