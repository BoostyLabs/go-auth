// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package go_auth

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/zeebo/errs"
)

// ClaimsError is an error class for Claims errors.
var ClaimsError = errs.Class("admin auth claims error")

// Claims represents data signed by server and used for authentication.
// TODO: add id everywhere.
type Claims struct {
	UserID    uuid.UUID `json:"userId"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expiresAt"`
}

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
