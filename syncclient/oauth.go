package syncclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mikescher/firefox-sync-client/x"
)

type oauthTokenRequestSchema struct {
	GrantType    string `json:"grant_type"`
	AccessType   string `json:"access_type,omitempty"`
	ClientID     string `json:"client_id"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type oauthTokenResponseSchema struct {
	AccessToken  string               `json:"access_token"`
	TokenType    string               `json:"token_type"`
	Scope        string               `json:"scope"`
	ExpiresIn    x.IntSecondsDuration `json:"expires_in"`
	AuthAt       int                  `json:"auth_at"`
	RefreshToken string               `json:"refresh_token"`
}

type scopedKeyDataRequestSchema struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

type scopedKeyDataResponseSchema map[string]struct {
	Identifier           string `json:"identifier"`
	KeyRotationSecret    string `json:"keyRotationSecret"`
	KeyRotationTimestamp int64  `json:"keyRotationTimestamp"`
}

const (
	oAuthClientID = "e7ce535d93522896"
	oAuthScope    = "https://identity.mozilla.com/apps/oldsync"
)

func (f *Client) AcquireOAuthToken(ctx context.Context, session KeyedSession) (OAuthSession, error) {
	debug("Create OAuth Token")

	t0 := time.Now()

	oAuthBody := oauthTokenRequestSchema{
		GrantType:  "fxa-credentials",
		AccessType: "offline",
		ClientID:   oAuthClientID,
		Scope:      oAuthScope,
	}

	binRespOAuth, _, err := f.requestWithHawkToken(ctx, "POST", "/oauth/token", oAuthBody, session.SessionToken, "sessionToken")
	if err != nil {
		return OAuthSession{}, fmt.Errorf("failed to request oauth-token: %w", err)
	}

	var respOAuth oauthTokenResponseSchema
	err = json.Unmarshal(binRespOAuth, &respOAuth)
	if err != nil {
		return OAuthSession{}, fmt.Errorf("failed to unmarshal oauth token response: %w", err)
	}

	debug("OAuth token",
		"AccessToken", respOAuth.AccessToken,
		"RefreshToken", respOAuth.RefreshToken,
		"Expiration", respOAuth.ExpiresIn)

	debug("Query ScopedKeyData")

	keyDataBody := scopedKeyDataRequestSchema{
		ClientID: oAuthClientID,
		Scope:    oAuthScope,
	}

	binRespScopedKeyData, _, err := f.requestWithHawkToken(ctx, "POST", "/account/scoped-key-data", keyDataBody, session.SessionToken, "sessionToken")
	if err != nil {
		return OAuthSession{}, fmt.Errorf("failed to request scoped-key-data: %w", err)
	}

	var respKeyData scopedKeyDataResponseSchema
	err = json.Unmarshal(binRespScopedKeyData, &respKeyData)
	if err != nil {
		return OAuthSession{}, fmt.Errorf("failed to unmarshal scoped key data response: %w", err)
	}

	data, ok := respKeyData[oAuthScope]
	if !ok {
		return OAuthSession{}, fmt.Errorf("scoped-key-data does not contain scope")
	}

	clientStateBin := sha256.Sum256(session.KeyB)
	clientStateB64 := base64.RawURLEncoding.EncodeToString(clientStateBin[0:16])
	keyID := fmt.Sprintf("%d-%s", data.KeyRotationTimestamp, clientStateB64)

	debug("Scoped key data",
		"KeyRotationTimestamp", data.KeyRotationTimestamp,
		"ClientState", clientStateB64,
		"KeyID", keyID)

	return session.Extend(respOAuth.AccessToken, respOAuth.RefreshToken, keyID, t0, time.Duration(respOAuth.ExpiresIn)), nil
}

// AcquireOAuthToken obtains an OAuth token using the provided session.
// It returns an OAuthSession containing the token and related information.
func (f *Client) RefreshOAuthToken(ctx context.Context, session KeyedSession, refreshToken string) (OAuthSession, error) {
	debug("Create OAuth Token (via refreshToken)")

	t0 := time.Now()

	oAuthBody := oauthTokenRequestSchema{
		GrantType:    "fxa-credentials",
		RefreshToken: refreshToken,
		ClientID:     oAuthClientID,
		Scope:        oAuthScope,
	}

	binRespOAuth, _, err := f.requestWithHawkToken(ctx, "POST", "/oauth/token", oAuthBody, session.SessionToken, "sessionToken")
	if err != nil {
		return OAuthSession{}, fmt.Errorf("failed to request oauth-token: %w", err)
	}

	var respOAuth oauthTokenResponseSchema
	err = json.Unmarshal(binRespOAuth, &respOAuth)
	if err != nil {
		return OAuthSession{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	debug("OAuth token",
		"AccessToken", respOAuth.AccessToken,
		"RefreshToken", respOAuth.RefreshToken,
		"Expiration", respOAuth.ExpiresIn)

	debug("Query ScopedKeyData")

	keyDataBody := scopedKeyDataRequestSchema{
		ClientID: oAuthClientID,
		Scope:    oAuthScope,
	}

	binRespScopedKeyData, _, err := f.requestWithHawkToken(ctx, "POST", "/account/scoped-key-data", keyDataBody, session.SessionToken, "sessionToken")
	if err != nil {
		return OAuthSession{}, fmt.Errorf("failed to request scoped-key-data: %w", err)
	}

	var respKeyData scopedKeyDataResponseSchema
	err = json.Unmarshal(binRespScopedKeyData, &respKeyData)
	if err != nil {
		return OAuthSession{}, fmt.Errorf("failed to unmarshal scoped key data response: %w", err)
	}

	data, ok := respKeyData[oAuthScope]
	if !ok {
		return OAuthSession{}, fmt.Errorf("scoped-key-data does not contain scope")
	}

	clientStateBin := sha256.Sum256(session.KeyB)
	clientStateB64 := base64.RawURLEncoding.EncodeToString(clientStateBin[0:16])
	keyID := fmt.Sprintf("%d-%s", data.KeyRotationTimestamp, clientStateB64)

	debug("Scoped key data",
		"KeyRotationTimestamp", data.KeyRotationTimestamp,
		"ClientState", clientStateB64,
		"KeyID", keyID)

	return session.Extend(respOAuth.AccessToken, refreshToken, keyID, t0, time.Duration(respOAuth.ExpiresIn)), nil
}

// RefreshSession refreshes an expired FFSyncSession using OAuth and HAWK authentication.
// It returns the updated session, a boolean indicating if refresh occurred, and any error.
func (f *Client) RefreshSession(ctx context.Context, session FFSyncSession, force bool) (FFSyncSession, bool, error) {
	if session.Expired() {
		debug("Refreshing session (OAuth refreshToken + HawkAuth)",
			"expiration", session.Timeout.In(f.TimeZone), "force", force)
	} else {
		debug("Session still valid", "expiration", session.Timeout.In(f.TimeZone))
		return session, false, nil
	}

	sessionOAuth, err := f.RefreshOAuthToken(ctx, session.ToKeyed(), session.RefreshToken)
	if err != nil {
		return FFSyncSession{}, false, fmt.Errorf("failed to refresh OAuth: %w", err)
	}

	sessionHawk, err := f.HawkAuth(ctx, sessionOAuth)
	if err != nil {
		return FFSyncSession{}, false, fmt.Errorf("failed to authenticate HAWK: %w", err)
	}

	sessionCrypto, err := f.GetCryptoKeys(ctx, sessionHawk)
	if err != nil {
		return FFSyncSession{}, false, fmt.Errorf("failed to get crypto/keys: %w", err)
	}

	keyBundles, err := sessionCrypto.KeyBundles()
	if err != nil {
		return FFSyncSession{}, false, fmt.Errorf("failed creating key bundles: %w", err)
	}

	cryptoSession := sessionHawk.Extend(keyBundles)

	return cryptoSession.Reduce(), true, nil
}
