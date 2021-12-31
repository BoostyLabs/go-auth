// Copyright (C) 2021-2022 Amuzed GmbH finn@amuzed.io.
// This file is part of the project AMUZED.
// AMUZED can not be copied and/or distributed without the express.
// permission of Amuzed GmbH.

package go_auth

import "golang.org/x/oauth2"

// GoogleOauth contains oath config.
type GoogleOauth struct {
	GoogleOauthConfig oauth2.Config
}
