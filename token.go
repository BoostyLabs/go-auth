// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package go_auth

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"strings"

	"github.com/zeebo/errs"
)

// TokenError is an error class for auth Token errors.
var TokenError = errs.Class("admin auth token error")

// Token represents authentication data structure.
type Token struct {
	Payload   []byte
	Signature []byte
}

// String returns base64URLEncoded data joined with.
func (t *Token) String() string {
	payload := base64.URLEncoding.EncodeToString(t.Payload)
	signature := base64.URLEncoding.EncodeToString(t.Signature)

	return strings.Join([]string{payload, signature}, ".")
}

// FromBase64URLString creates Token instance from base64URLEncoded string representation.
func FromBase64URLString(token string) (Token, error) {
	i := strings.Index(token, ".")
	if i < 0 {
		return Token{}, TokenError.New("invalid token format")
	}

	payload := token[:i]
	signature := token[i+1:]

	payloadDecoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(payload)))
	signatureDecoder := base64.NewDecoder(base64.URLEncoding, bytes.NewReader([]byte(signature)))

	payloadBytes, err := ioutil.ReadAll(payloadDecoder)
	if err != nil {
		return Token{}, TokenError.New("decoding token's signature failed: %s", err)
	}

	signatureBytes, err := ioutil.ReadAll(signatureDecoder)
	if err != nil {
		return Token{}, TokenError.New("decoding token's body failed: %s", err)
	}

	return Token{Payload: payloadBytes, Signature: signatureBytes}, nil
}
