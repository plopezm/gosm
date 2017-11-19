package support

import (
	"crypto/rsa"
	"io/ioutil"
	"strconv"

	jwt "github.com/dgrijalva/jwt-go"
)

//JWKInfo returns the public key in JWK
type JWKInfo struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

//GetJWTKeys generates JWT keys and JWT info
func GetJWTKeys(kid string, privKey string, pubKey string) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, jwkInfo *JWKInfo) {
	var err error
	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(readFile("jwtpriv.pem"))
	check(err)
	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(readFile("jwtpub.pem"))
	check(err)
	jwkInfo = &JWKInfo{
		Kty: "RSA",
		N:   publicKey.N.String(),
		E:   strconv.Itoa(publicKey.E),
		Alg: "RS512",
		Kid: kid,
	}
	return privateKey, publicKey, jwkInfo
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
