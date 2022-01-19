// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package goauth

import (
	"bytes"
	"encoding/json"

	"github.com/zeebo/errs"
)

// ClaimsError is an error class for Claims errors.
var ClaimsError = errs.Class("admin auth claims error")

// Claims represents data signed by server and used for authentication.
type Claims map[string]string

// JSON returns json representation of Claims.
func (c *Claims) JSON() ([]byte, error) {
	buffer := bytes.NewBuffer(nil)

	err := json.NewEncoder(buffer).Encode(c)
	return buffer.Bytes(), ClaimsError.Wrap(err)
}

// FromJSON returns Claims instance, parsed from JSON.
func FromJSON(data []byte) (*Claims, error) {
	claims := new(Claims)

	err := json.NewDecoder(bytes.NewReader(data)).Decode(claims)
	if err != nil {
		return nil, ClaimsError.Wrap(err)
	}

	return claims, nil
}
