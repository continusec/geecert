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
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	ErrInvalidIDToken = errors.New("ErrInvalidIDToken")
)

type IDTokenClaims struct {
	EmailAddress string
	FirstName    string
	LastName     string
}

func errIsClock(err error) bool {
	return err != nil && err.Error() == "Token used before issued"
}

func ValidateTokenWithRetryForClock(validator IDTokenValidator, idToken string, retries int) (*IDTokenClaims, error) {
	var rv *IDTokenClaims
	var err error
	for done, attempts := false, 0; !done; attempts++ {
		rv, err = validator.ValidateIDToken(idToken)
		if errIsClock(err) {
			if attempts < retries {
				log.Print("Token appears to have come from the future - retrying in 1 second.")
				time.Sleep(time.Second)
			} else {
				done = true
			}
		} else {
			done = true
		}
	}
	return rv, err
}

type IDTokenValidator interface {
	// Validates a token, including that it matchines the client ID and hosted domain
	// Returns the email address and nil upon success
	ValidateIDToken(idToken string) (*IDTokenClaims, error)
}

type OOIDClient interface {
	IDTokenValidator

	GetAuthRedirect(redir string) (string, error)
	GetTokenExchangeEndpoint() (string, error)
}

type OIDCIDTokenValidator struct {
	ConfigurationURL string
	ClientID         string
	HostedDomain     string

	AudienceInAppID          bool // if set verify "appid" claim for client ID, INSTEAd OF "aud" claim - useful for Azure Access Token
	GetHostedDomainFromEmail bool // if set, check for suffix in email field instead of "hd" cliam. useful for Azure Access Token
	SkipEmailVerified        bool // if set, don't require email_verified field. Useful for Azure Access token

	wkcMU sync.Mutex
	wkc   *wellKnownConfig // once set is never changed (else we need to do more locking..)
	kk    *keyCache        // once set is never changed (else we need to do more locking..)
}

type wellKnownConfig struct {
	Issuer   string `json:"issuer"`
	AuthURI  string `json:"authorization_endpoint"`
	TokenURI string `json:"token_endpoint"`
	JWKSURI  string `json:"jwks_uri"`
}

func (v *OIDCIDTokenValidator) ensureHasConfig() error {
	v.wkcMU.Lock()
	defer v.wkcMU.Unlock()

	if v.wkc != nil {
		return nil
	}

	resp, err := http.Get(v.ConfigurationURL)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return ErrUnexpectedServerResponse
	}
	defer resp.Body.Close()

	var rv wellKnownConfig
	err = json.NewDecoder(resp.Body).Decode(&rv)
	if err != nil {
		return err
	}
	v.wkc = &rv
	v.kk = &keyCache{
		JWKSURL:  rv.JWKSURI,
		Interval: time.Minute * 5,
	}
	return nil
}

func (v *OIDCIDTokenValidator) GetAuthRedirect(redir string) (string, error) {
	err := v.ensureHasConfig()
	if err != nil {
		return "", err
	}
	return v.wkc.AuthURI + "?" + url.Values{
		"scope":         {"email"},
		"redirect_uri":  {redir},
		"response_type": {"code"},
		"client_id":     {v.ClientID},
	}.Encode(), nil
}

func (v *OIDCIDTokenValidator) GetTokenExchangeEndpoint() (string, error) {
	err := v.ensureHasConfig()
	if err != nil {
		return "", err
	}
	return v.wkc.TokenURI, nil
}

// Validates a token, including that it matchines the client ID and hosted domain
// Returns the email address and nil upon success
func (v *OIDCIDTokenValidator) ValidateIDToken(idToken string) (*IDTokenClaims, error) {
	token, err := jwt.Parse(idToken, v.keyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, ErrInvalidIDToken
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidIDToken
	}
	err = v.ensureHasConfig() // we kind of know this was already called as a side-effect of v.keyFunc above, but we know what they say about assumptions, so we'll call again
	if err != nil {
		return nil, err
	}
	if !mapClaims.VerifyIssuer(v.wkc.Issuer, true) {
		return nil, ErrInvalidIDToken
	}
	if v.AudienceInAppID { // Azure won't refesh ID Tokens, so we use Access Token and verifiy the "appid" field instead of "aud"
		appID, ok := mapClaims["appid"]
		if !ok {
			return nil, ErrInvalidIDToken
		}
		appIDS, ok := appID.(string)
		if !ok {
			return nil, ErrInvalidIDToken
		}
		if appIDS != v.ClientID {
			return nil, ErrInvalidIDToken
		}
	} else {
		if !mapClaims.VerifyAudience(v.ClientID, true) {
			return nil, ErrInvalidIDToken
		}
	}

	// Email
	email, ok := mapClaims["email"]
	if !ok {
		return nil, ErrInvalidIDToken
	}

	emails, ok := email.(string)
	if !ok {
		return nil, ErrInvalidIDToken
	}

	// Check hosted domain
	if v.GetHostedDomainFromEmail {
		if !strings.HasSuffix(emails, "@"+v.HostedDomain) {
			return nil, ErrInvalidIDToken
		}
	} else {
		hd, ok := mapClaims["hd"]
		if !ok {
			return nil, ErrInvalidIDToken
		}
		hds, ok := hd.(string)
		if !ok {
			return nil, ErrInvalidIDToken
		}
		if hds != v.HostedDomain {
			return nil, ErrInvalidIDToken
		}
	}

	// Check email verified
	if !v.SkipEmailVerified {
		ev, ok := mapClaims["email_verified"]
		if !ok {
			return nil, ErrInvalidIDToken
		}
		evb, ok := ev.(bool)
		if !ok {
			return nil, ErrInvalidIDToken
		}
		if !evb {
			return nil, ErrInvalidIDToken
		}
	}

	// Start setting up return value
	rv := &IDTokenClaims{
		EmailAddress: emails,
	}

	// Try to get first name, it's OK if it fails
	firstName, ok := mapClaims["given_name"]
	if ok {
		nameAsString, ok := firstName.(string)
		if ok {
			rv.FirstName = nameAsString
		}
	}

	// Try to get last name, it's OK if it fails
	lastName, ok := mapClaims["family_name"]
	if ok {
		nameAsString, ok := lastName.(string)
		if ok {
			rv.LastName = nameAsString
		}
	}

	return rv, nil
}
