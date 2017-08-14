/*

Copyright 2017 Continusec Pty Ltd

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
	"errors"
	"log"
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

func ValidateTokenWithRetryForClock(idToken, clientID, hostedDomain string, retries int) (*IDTokenClaims, error) {
	var rv *IDTokenClaims
	var err error
	for done, attempts := false, 0; !done; attempts++ {
		rv, err = ValidateIDToken(idToken, clientID, hostedDomain)
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

// Validates a token, including that it matchines the client ID and hosted domain
// Returns the email address and nil upon success
func ValidateIDToken(idToken, clientID, hostedDomain string) (*IDTokenClaims, error) {
	token, err := jwt.Parse(idToken, GoogleKeyFunc)
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
	if !mapClaims.VerifyIssuer("accounts.google.com", true) {
		return nil, ErrInvalidIDToken
	}
	if !mapClaims.VerifyAudience(clientID, true) {
		return nil, ErrInvalidIDToken
	}

	// Check hosted domain
	hd, ok := mapClaims["hd"]
	if !ok {
		return nil, ErrInvalidIDToken
	}
	hds, ok := hd.(string)
	if !ok {
		return nil, ErrInvalidIDToken
	}
	if hds != hostedDomain {
		return nil, ErrInvalidIDToken
	}

	// Check email verified
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

	// Email
	email, ok := mapClaims["email"]
	if !ok {
		return nil, ErrInvalidIDToken
	}

	emails, ok := email.(string)
	if !ok {
		return nil, ErrInvalidIDToken
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
