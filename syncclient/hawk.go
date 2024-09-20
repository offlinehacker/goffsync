package syncclient

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (f *Client) HawkAuth(ctx context.Context, session OAuthSession) (HawkSession, error) {
	sha := sha256.New()
	sha.Write(session.KeyB)
	sessionState := hex.EncodeToString(sha.Sum(nil)[0:16])

	debug("Authenticate HAWK",
		"Session-State", sessionState,
		"AccessToken", session.AccessToken,
		"KeyID", session.KeyID)

	req, err := http.NewRequestWithContext(ctx, "GET", f.TokenServerURL+"/1.0/sync/1.5", nil)
	if err != nil {
		return HawkSession{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+session.AccessToken)
	req.Header.Add("X-KeyID", session.KeyID)

	debug("Query HAWK credentials")

	t0 := time.Now()

	rawResp, err := f.client().Do(req)
	if err != nil {
		return HawkSession{}, fmt.Errorf("hawk request error: %w", err)
	}

	respBodyRaw, err := io.ReadAll(rawResp.Body)
	if err != nil {
		return HawkSession{}, fmt.Errorf("failed to read response-body request: %w", err)
	}

	if rawResp.StatusCode != 200 {
		if len(string(respBodyRaw)) > 1 {
			return HawkSession{},
				fmt.Errorf("%w: api call returned statuscode %d\nBody:\n%s", ErrInternal, rawResp.StatusCode, respBodyRaw)
		}

		return HawkSession{}, fmt.Errorf("%w: api call returned statuscode %d", ErrInternal, rawResp.StatusCode)
	}

	var resp hawkCredResponseSchema
	err = json.Unmarshal(respBodyRaw, &resp)
	if err != nil {
		return HawkSession{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	hawkTimeOut := t0.Add(time.Second * time.Duration(resp.Duration))

	debug("HAWK resp",
		"HAWK-ID", resp.ID,
		"HAWK-Key", resp.Key,
		"HAWK-UserID", resp.UID,
		"HAWK-Endpoint", resp.APIEndpoint,
		"HAWK-Duration", resp.Duration,
		"HAWK-HashAlgo", resp.HashAlgorithm,
		"HAWK-FxA-Uid", resp.HashedFxAUID,
		"HAWK-NodeType", resp.NodeType,
		"HAWK-Timeout", hawkTimeOut)

	if resp.HashAlgorithm != "sha256" {
		return HawkSession{},
			fmt.Errorf("HAWK-HashAlgorithm '%s' is currently not supported", resp.HashAlgorithm)
	}

	cred := HawkCredentials{
		HawkID:            resp.ID,
		HawkKey:           resp.Key,
		APIEndpoint:       resp.APIEndpoint,
		HawkHashAlgorithm: resp.HashAlgorithm,
	}

	return session.Extend(cred, hawkTimeOut), nil
}

func calcHawkTokenAuth(token []byte, tokentype string, requestMethod string, requestURI string, body string) (string, []byte, error) {
	keyMaterial, err := deriveKey(token, tokentype, 3*32)
	if err != nil {
		return "", nil, fmt.Errorf("failed to derive hawkTokenAuth key")
	}

	id := hex.EncodeToString(keyMaterial[:32])
	authKey := keyMaterial[32:64]
	bundleKey := keyMaterial[64:]

	auth, err := calcHawkAuth(requestMethod, requestURI, body, "application/json", authKey, id)
	if err != nil {
		return "", nil, fmt.Errorf("failed to calc hawk auth")
	}
	return auth, bundleKey, nil
}

func calcHawkSessionAuth(session FFSyncSession, requestMethod string, requestURI string, body string, contentType string) (string, error) {
	if session.HawkHashAlgorithm != "sha256" {
		return "", fmt.Errorf("invalid hawk Hash-Algo: %s", session.HawkHashAlgorithm)
	}

	auth, err := calcHawkAuth(requestMethod, requestURI, body, contentType, []byte(session.HawkKey), session.HawkID)
	if err != nil {
		return "", fmt.Errorf("failed to calc hawk auth: %w", err)
	}
	return auth, nil
}

func calcHawkAuth(requestMethod string, requestURI string, body string, contentType string, hawkKey []byte, hawkID string) (string, error) {
	hashStr := "hawk.1.payload\n" + contentType + "\n" + body + "\n"

	rawHash := sha256.Sum256([]byte(hashStr))

	hash := base64.StdEncoding.EncodeToString(rawHash[:])
	if requestMethod == "GET" || body == "" {
		hash = ""
	}

	nonce := base64.StdEncoding.EncodeToString(randBytes(5))
	ts := fmt.Sprintf("%d", time.Now().Unix())

	requrl, err := url.Parse(requestURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse requestURI: %s", requestURI)
	}

	uhost := requrl.Host
	uport := "80"
	if requrl.Scheme == "https" {
		uport = "443"
	}
	if strings.Contains(uhost, ":") {
		_v := uhost
		uhost = _v[0:strings.Index(_v, "=")]
		uport = _v[strings.Index(_v, "=")+1:]
	}

	rpath := requrl.EscapedPath()
	if requrl.RawQuery != "" {
		rpath += "?" + requrl.RawQuery
	}

	sigbits := make([]string, 0, 10)
	sigbits = append(sigbits, "hawk.1.header")
	sigbits = append(sigbits, ts)
	sigbits = append(sigbits, nonce)
	sigbits = append(sigbits, requestMethod)
	sigbits = append(sigbits, rpath)
	sigbits = append(sigbits, strings.ToLower(uhost))
	sigbits = append(sigbits, strings.ToLower(uport))
	sigbits = append(sigbits, hash)
	sigbits = append(sigbits, "")
	sigbits = append(sigbits, "")

	sigstr := strings.Join(sigbits, "\n")

	hmacBuilder := hmac.New(sha256.New, hawkKey)
	hmacBuilder.Write([]byte(sigstr))
	mac := base64.StdEncoding.EncodeToString(hmacBuilder.Sum(nil))

	hdr := `Hawk ` +
		`id="` + hawkID + `", ` +
		`mac="` + mac + `", ` +
		`ts="` + ts + `", ` +
		`nonce="` + nonce + `"`

	if hash != "" {
		hdr += `, hash="` + hash + `"`
	}

	return hdr, nil
}
