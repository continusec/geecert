/*

Copyright 2018 Continusec Pty Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package geecert

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrUnexpectedAlgorithm      = errors.New("ErrUnexpectedAlgorithm")
	ErrMissingKeyID             = errors.New("ErrMissingKeyID")
	ErrMissingCertificate       = errors.New("ErrMissingCertificate")
	ErrUnexpectedServerResponse = errors.New("ErrUnexpectedServerResponse")
	ErrCertificateNotValid      = errors.New("ErrCertificateNotValid")
)

// ensureConfig *must* be called
func (v *OIDCIDTokenValidator) keyFunc(t *jwt.Token) (interface{}, error) {
	err := v.ensureHasConfig()
	if err != nil {
		return nil, err
	}

	// Ensure that RS256 is used. This might seem overkill to care,
	// but since the JWT spec actually allows a None algorithm which
	// we definitely don't want, so instead we whitelist what we will allow.
	if t.Method.Alg() != "RS256" {
		return nil, ErrUnexpectedAlgorithm
	}

	// Get Key ID
	kid, ok := t.Header["kid"]
	if !ok {
		return nil, ErrMissingKeyID
	}

	kidS, ok := kid.(string)
	if !ok {
		return nil, ErrMissingKeyID
	}

	// Get key from cache
	return v.kk.Get(kidS)
}

type keyCache struct {
	JWKSURL  string
	Interval time.Duration

	updateLock     sync.Mutex
	readLock       sync.Mutex
	keys           map[string]*rsa.PublicKey
	earliestUpdate time.Time
}

// Looks for the certificate with given ID. If not found, and not recently
// updated, then update the cache
func (cc *keyCache) Get(kid string) (*rsa.PublicKey, error) {
	cc.readLock.Lock()
	rv, ok := cc.keys[kid]
	cc.readLock.Unlock()
	if ok {
		return rv, nil
	}

	err := cc.Update()
	if err != nil {
		return nil, err
	}

	cc.readLock.Lock()
	rv, ok = cc.keys[kid]
	cc.readLock.Unlock()
	if ok {
		return rv, nil
	}

	return nil, ErrMissingCertificate
}

type jwkResp struct {
	Keys []struct {
		KID string `json:"kid"`
		KTY string `json:"kty"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// Updates the cache if past interval.
func (cc *keyCache) Update() error {
	cc.updateLock.Lock()
	defer cc.updateLock.Unlock()

	// Leave early if we've updated recently
	if time.Now().Before(cc.earliestUpdate) {
		return nil
	}

	resp, err := http.Get(cc.JWKSURL)
	if err != nil {
		return err
	}

	// Always read body, even if not 200 as it can contain info about the err
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Fail if not OK
	if resp.StatusCode != http.StatusOK {
		return ErrUnexpectedServerResponse
	}

	var keys jwkResp
	err = json.Unmarshal(body, &keys)
	if err != nil {
		return ErrUnexpectedServerResponse
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, k := range keys.Keys {
		if k.Use != "sig" {
			continue
		}
		if k.KTY != "RSA" {
			continue
		}
		eB, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return ErrUnexpectedServerResponse
		}
		nB, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return ErrUnexpectedServerResponse
		}

		newKeys[k.KID] = &rsa.PublicKey{
			N: (&big.Int{}).SetBytes(nB),
			E: int((&big.Int{}).SetBytes(eB).Int64()),
		}
	}

	cc.readLock.Lock()
	cc.keys = newKeys
	cc.readLock.Unlock()

	cc.earliestUpdate = time.Now().Add(cc.Interval)

	return nil
}
