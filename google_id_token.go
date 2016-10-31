/*

Copyright 2016 Continusec Pty Ltd

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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	GoogleCertificateURL = "https://www.googleapis.com/oauth2/v1/certs"
)

var (
	ErrUnexpectedAlgorithm      = errors.New("ErrUnexpectedAlgorithm")
	ErrMissingKeyID             = errors.New("ErrMissingKeyID")
	ErrMissingCertificate       = errors.New("ErrMissingCertificate")
	ErrUnexpectedServerResponse = errors.New("ErrUnexpectedServerResponse")
	ErrCertificateNotValid      = errors.New("ErrCertificateNotValid")
)

func GoogleKeyFunc(t *jwt.Token) (interface{}, error) {
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

	// Get Cert
	cert, err := GoogleCache.Get(kidS)
	if err != nil {
		return nil, err
	}

	// TODO - figure out why we need to mess with the cert
	cert.IsCA = true
	cert.KeyUsage |= x509.KeyUsageCertSign

	cp := x509.NewCertPool()
	cp.AddCert(cert)
	_, err = cert.Verify(x509.VerifyOptions{
		DNSName:   "federated-signon.system.gserviceaccount.com",
		Roots:     cp,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, err
	}

	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrUnexpectedAlgorithm
	}

	return rsaKey, nil
}

type CertificateCache struct {
	URL      string
	Interval time.Duration

	updateLock     sync.Mutex
	readLock       sync.Mutex
	certs          map[string]*x509.Certificate
	earliestUpdate time.Time
}

var GoogleCache = &CertificateCache{
	URL:      GoogleCertificateURL,
	Interval: 5 * time.Minute,
}

// Looks for the certificate with given ID. If not found, and not recently
// updated, then update the cache
func (cc *CertificateCache) Get(kid string) (*x509.Certificate, error) {
	cc.readLock.Lock()
	rv, ok := cc.certs[kid]
	cc.readLock.Unlock()
	if ok {
		return rv, nil
	}

	err := cc.Update()
	if err != nil {
		return nil, err
	}

	cc.readLock.Lock()
	rv, ok = cc.certs[kid]
	cc.readLock.Unlock()
	if ok {
		return rv, nil
	}

	return nil, ErrMissingCertificate
}

// Updates the cache if past interval.
func (cc *CertificateCache) Update() error {
	cc.updateLock.Lock()
	defer cc.updateLock.Unlock()

	// Leave early if we've updated recently
	if time.Now().Before(cc.earliestUpdate) {
		return nil
	}

	resp, err := http.Get(cc.URL)
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

	var certsRaw interface{}
	err = json.Unmarshal(body, &certsRaw)
	if err != nil {
		return ErrUnexpectedServerResponse
	}

	certs, ok := certsRaw.(map[string]interface{})
	if !ok {
		return ErrUnexpectedServerResponse
	}

	newCerts := make(map[string]*x509.Certificate)
	for k, v := range certs {
		vString, ok := v.(string)
		if !ok {
			return ErrUnexpectedServerResponse
		}

		// Decode PEM
		block, _ := pem.Decode([]byte(vString))
		if block == nil {
			return ErrUnexpectedServerResponse
		}
		if block.Type != "CERTIFICATE" {
			return ErrUnexpectedServerResponse
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		newCerts[k] = cert
	}

	cc.readLock.Lock()
	cc.certs = newCerts
	cc.readLock.Unlock()

	cc.earliestUpdate = time.Now().Add(cc.Interval)

	return nil
}
