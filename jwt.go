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
	"errors"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	ErrInvalidIDToken = errors.New("ErrInvalidIDToken")
)

func ValidateIDToken(idToken, clientID, hostedDomain string) (string, error) {
	token, err := jwt.Parse(idToken, GoogleKeyFunc)
	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", ErrInvalidIDToken
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrInvalidIDToken
	}
	if !mapClaims.VerifyIssuer("accounts.google.com", true) {
		return "", ErrInvalidIDToken
	}
	if !mapClaims.VerifyAudience(clientID, true) {
		return "", ErrInvalidIDToken
	}

	// Check hosted domain
	hd, ok := mapClaims["hd"]
	if !ok {
		return "", ErrInvalidIDToken
	}
	hds, ok := hd.(string)
	if !ok {
		return "", ErrInvalidIDToken
	}
	if hds != hostedDomain {
		return "", ErrInvalidIDToken
	}

	// Check email verified
	ev, ok := mapClaims["email_verified"]
	if !ok {
		return "", ErrInvalidIDToken
	}
	evb, ok := ev.(bool)
	if !ok {
		return "", ErrInvalidIDToken
	}
	if !evb {
		return "", ErrInvalidIDToken
	}

	// Email
	email, ok := mapClaims["email"]
	if !ok {
		return "", ErrInvalidIDToken
	}

	emails, ok := email.(string)
	if !ok {
		return "", ErrInvalidIDToken
	}

	return emails, nil
}
