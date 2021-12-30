// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package go_auth

import (
	"net/http"
	"time"
)

// CookieSettings variable cookie settings.
type CookieSettings struct {
	Name string
	Path string
}

// CookieAuth handles cookie authorization.
type CookieAuth struct {
	settings CookieSettings
}

// NewCookieAuth create new cookie authorization with provided settings.
func NewCookieAuth(settings CookieSettings) *CookieAuth {
	return &CookieAuth{
		settings: settings,
	}
}

// GetToken retrieves token from request.
func (cookieAuth *CookieAuth) GetToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(cookieAuth.settings.Name)
	if err != nil {
		return "", err
	}

	return cookie.Value, nil
}

// SetTokenCookie sets parametrized token cookie that is not accessible from js.
func (cookieAuth *CookieAuth) SetTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAuth.settings.Name,
		Value:    token,
		Path:     cookieAuth.settings.Path,
		Expires:  time.Now().Add(time.Hour * 24),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// RemoveTokenCookie removes auth cookie that is not accessible from js.
func (cookieAuth *CookieAuth) RemoveTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAuth.settings.Name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}
