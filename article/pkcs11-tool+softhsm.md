# pkcs11-tool, sotfhsm 실습
#개인공부/암호학

## 설치하기
### 파일 위치 찾기
```
find / -name “libsofthsm2.so”
```
### 어떤 파일에 접근이 거부되었는지 확인하기
```
strace 명령어 2>&1 | grep 시스템콜
```
* 해당 명령어를 실행했을 때의 syscall가 stdout으로 나갈 때, 그것을 받아와 stdin으로 넣어서 pipe로 받아 grep으로 해당 syscall의 이름을 포함한 syscall들을 보여줌
### 사용자 정보 확인(UID, GID, 속한 Groups등의 정보)
```
id
```
- - - -
## 파티션 관리
* “slot”이나 “token”의 용어는 파티션이라고 생각하면 됨
### 파티션 목록 확인
```
pkcs11-tool ——module $LIB ——list-slots
```
### 새 파티션 생성
```
pkcs11-tool ——module $LIB ——init-token ——slot 0 ——label (Partition Label값) ——so-pin (Security Officer PIN값)
```
### 새 파티션의 User PIN을 설정
* SO PIN으로 User PIN을 리셋할 수 있음
```
pkcs11-tool ——module $LIB ——init-pin ——slot $SLOT ——login ——login-type so ——so-pin(SO PIN값) ——new-pin (새로운 User PIN값)
```
- - - -
## 오브젝트 관리
### 오브젝트 목록 출력
```
pkcs11-tool ——module $LIB ——slot $SLOT ——list-objects
```
### 2048비트 RSA 키 쌍 생성
> https://verschlüsselt.it/generate-rsa-ecc-and-aes-keys-with-opensc-pkcs11-tool/  
```
pkcs11-tool ——module $LIB ——slot $SLOT \
——label (오브젝트 라벨) \
——keypairgen ——id (오브젝트 ID) ——key-type rsa:2048 \
——login ——login-type user
```
### hsm에서 생성한 공개키 pkcs#11로 export하기
> https://verschlüsselt.it/export-a-rsa-ecc-public-key-with-opensc-pkcs11-tool/  
```
pkcs11-tool ——module $LIB ——slot $SLOT ——read-object ——type pubkey ——id (오브젝트 id) -o (생성할 파일 이름)
```
### DEM포맷의 공개키 -> PEM포맷의 공개키로 전환
```
openssl rsa -pubin -inform DEM -in (DEM파일) -pubout -outform PEM -out (PEM파일)
```
### AES-256 생성하기
```
pkcs11-tool ——module $LIB ——slot $SLOT \
——label myaeskey \
——keygen ——id 2 ——key-type aes:32 \
——login ——login-type user
```
* aes:32라고 하는 이유는 32가 bit가 아닌 byte여서 32*8 = 256이기 때문
### ECDSA secp256r1 생성하기
```
pkcs11-tool ——module $LIB ——slot $SLOT \
——label myeckey \
—keypairgen —id 3 —key-type EC:prime256v1 \
—login —login-type user
```
### EC 키 쌍의 공개키 추출하여 파일로 저장하기
```
pkcs11-tool —module $LIB —slot $SLOT —read-object —type pubkey —id (오브젝트 id) -o (생성할 파일 이름)
```
### 추출한 EC 공개키를 PEM으로 변환하기
```
openssl ec -inform DEM -pubin -in (DEM공개키) -outform PEM -pubout -out (PEM공개키)
```
