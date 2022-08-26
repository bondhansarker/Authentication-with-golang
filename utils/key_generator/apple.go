package key_generator

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"auth/utils/log"
)

// key object fetched from APPLE_KEYS_URL
type AppleKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func GetApplePublicKeys(appleKeyUrl string, timeOut time.Duration) ([]AppleKey, error) {

	var c http.Client
	var req *http.Request
	var resp *http.Response
	var bodyContents []byte
	var err error
	var keys struct {
		Keys []AppleKey `json:"keys"`
	}

	c = http.Client{Timeout: timeOut * time.Second}
	req, err = http.NewRequest("GET", appleKeyUrl, nil)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	resp, err = c.Do(req)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	bodyContents, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	err = json.Unmarshal(bodyContents, &keys)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return keys.Keys, nil
}

func GetPublicKeyObject(base64urlEncodedN string, base64urlEncodedE string) *rsa.PublicKey {

	var pub rsa.PublicKey
	var decE, decN []byte
	var eInt int
	var err error

	// get the modulo
	decN, err = base64.RawURLEncoding.DecodeString(base64urlEncodedN)
	if err != nil {
		return nil
	}
	pub.N = new(big.Int)
	pub.N.SetBytes(decN)
	// get exponent
	decE, err = base64.RawURLEncoding.DecodeString(base64urlEncodedE)
	if err != nil {
		return nil
	}
	// convert the bytes into int
	for _, v := range decE {
		eInt = eInt << 8
		eInt = eInt | int(v)
	}
	pub.E = eInt

	return &pub
}
