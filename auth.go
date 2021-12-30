// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package go_auth

import (
	"context"
	"github.com/zeebo/errs"
)

// Error is an error class for auth errors.
var Error = errs.Class("auth error")

// Key is an enumeration for different auth keys for context.
type Key int

const (
	// KeyClaims is a key to receive auth result from context - claims or error.
	KeyClaims Key = 0
	// KeyToken is a key to receive auth token from context.
	KeyToken Key = 1
)

// SetClaims creates new context with Claims.
func SetClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, KeyClaims, claims)
}

// GetClaims gets Claims from context.
func GetClaims(ctx context.Context) (Claims, error) {
	value := ctx.Value(KeyClaims)

	if auth, ok := value.(Claims); ok {
		return auth, nil
	}

	if err, ok := value.(error); ok {
		return Claims{}, Error.Wrap(err)
	}

	return Claims{}, Error.New("could not get auth or error from context")
}

// SetToken creates context with auth token.
func SetToken(ctx context.Context, key []byte) context.Context {
	return context.WithValue(ctx, KeyToken, key)
}

// GetToken returns auth token from context is exists.
func GetToken(ctx context.Context) ([]byte, bool) {
	key, ok := ctx.Value(KeyToken).([]byte)
	return key, ok
}
