package rsastore

import (
	"crypto/rsa"
	"io/ioutil"
	"strconv"

	"github.com/dgrijalva/jwt-go"
)

//JwkRsa returns the public key in JWK
type JwkRsa struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

//RsaKeystore contains the Public & Private RSA Keys
type RsaKeystore struct {
	Kid        string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

//GetJWK returns a JWK with the public key
func (keystore *RsaKeystore) GetJWK() *JwkRsa {
	return &JwkRsa{
		Kty: "RSA",
		N:   keystore.PublicKey.N.String(),
		E:   strconv.Itoa(keystore.PublicKey.E),
		Alg: "RS512",
		Kid: keystore.Kid,
	}
}

//GetJWTKeys generates JWT keys and JWT info
func GetJWTKeys(kid string, privKey string, pubKey string) (keystore *RsaKeystore) {
	var err error
	keystore = &RsaKeystore{}

	keystore.Kid = kid
	keystore.PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(readFile("jwtpriv.pem"))
	check(err)
	keystore.PublicKey, err = jwt.ParseRSAPublicKeyFromPEM(readFile("jwtpub.pem"))
	check(err)

	return keystore
}

func readFile(file string) []byte {
	dat, err := ioutil.ReadFile(file)
	check(err)
	//fmt.Print(string(dat))
	return dat
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
