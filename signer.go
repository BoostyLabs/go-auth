// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package goauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/zeebo/errs"
)

// TokenSignerError is an error class for TokenSigner errors.
var TokenSignerError = errs.Class("auth token signer error")

// TokenSigner creates signature for provided auth Token. Its hmac256 based TokenSigner.
type TokenSigner struct {
	Secret []byte
}

// SignToken signs token with some secret key.
func (a *TokenSigner) SignToken(token *Token) error {
	mac := hmac.New(sha256.New, a.Secret)

	encoded := base64.URLEncoding.EncodeToString(token.Payload)

	_, err := mac.Write([]byte(encoded))
	if err != nil {
		return TokenSignerError.Wrap(err)
	}

	token.Signature = mac.Sum(nil)

	return nil
}

// CreateToken creates string representation.
func (a *TokenSigner) CreateToken(ctx context.Context, claims *Claims) (string, error) {
	json, err := claims.JSON()
	if err != nil {
		return "", TokenSignerError.Wrap(err)
	}

	token := Token{Payload: json}
	err = a.SignToken(&token)
	if err != nil {
		return "", TokenSignerError.Wrap(err)
	}

	return token.String(), nil
}
