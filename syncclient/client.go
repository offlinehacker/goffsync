package syncclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

const FFSCLIENT_VERSION = "1.8.0"

type Client struct {
	client func() *http.Client

	ServerURL string
	AuthURL   string

	MaxRetries        int
	RequestTimeout    time.Duration
	RequestX509Ignore bool
	TimeZone          *time.Location
}

func New() *Client {
	c := &Client{TimeZone: time.Local}
	c.client = sync.OnceValue(c.getClient)

	return c
}

func (c *Client) getClient() *http.Client {
	var hc *http.Client = &http.Client{}

	if c.MaxRetries > 0 {
		retryClient := retryablehttp.NewClient()
		retryClient.RetryMax = c.MaxRetries

		hc = retryClient.StandardClient()
	}

	if c.RequestTimeout > 0 {
		hc.Timeout = c.RequestTimeout
	}

	// custom transport that ignore x509 errors
	if c.RequestX509Ignore {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

		hc.Transport = t
	}

	return hc
}

func (f Client) DeleteAllData(ctx context.Context, session FFSyncSession) error {
	_, err := f.request(ctx, session, http.MethodDelete, "", nil)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}

	return nil
}

func (f Client) CheckSession(ctx context.Context, session FFSyncSession) (bool, error) {
	binResp, _, err := f.requestWithHawkToken(ctx, "GET", "/session/status", nil, session.SessionToken, "sessionToken")
	if err != nil {
		return false, fmt.Errorf("API request failed: %w", err)
	}

	var resp sessionStatusResponseSchema
	err = json.Unmarshal(binResp, &resp)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if resp.State != "verified" {
		return false, nil
	}

	if resp.UserID != session.UserId {
		return false, nil
	}

	return true, nil
}

func (f Client) requestWithHawkToken(ctx context.Context, method string, relurl string, body any, token []byte, tokenType string) ([]byte, []byte, error) {
	requestURL := f.AuthURL + relurl

	var outBundleKey []byte

	auth := func(method string, url string, body string, contentType string) (string, error) {
		hawkAuth, hawkBundleKey, err := calcHawkTokenAuth(token, tokenType, method, url, body)
		if err != nil {
			return "", fmt.Errorf("failed to create hawk-auth: %w", err)
		}
		outBundleKey = hawkBundleKey
		return hawkAuth, nil
	}

	res, err := f.internalRequest(ctx, auth, method, requestURL, body)
	if err != nil {
		return nil, nil, err
	}

	return res, outBundleKey, nil
}

func (f *Client) request(ctx context.Context, session FFSyncSession, method string, relurl string, body any) ([]byte, error) {
	requestURL := session.APIEndpoint + relurl

	auth := func(method string, url string, body string, contentType string) (string, error) {
		hawkAuth, err := calcHawkSessionAuth(session, method, url, body, contentType)
		if err != nil {
			return "", fmt.Errorf("failed to create hawk-auth: %w", err)
		}

		return hawkAuth, nil
	}

	return f.internalRequest(ctx, auth, method, requestURL, body)
}

func (f *Client) internalRequest(ctx context.Context, auth func(method string, url string, body string, contentType string) (string, error), method string, requestURL string, body any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	err := encoder.Encode(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("User-Agent", "firefox-sync-client/"+FFSCLIENT_VERSION)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Host", req.URL.Host)

	hawkAuth, err := auth(req.Method, req.URL.String(), buf.String(), "application/json")
	if err != nil {
		return nil, fmt.Errorf("failed to create auth: %w", err)
	}

	req.Header.Add("Authorization", hawkAuth)

	rawResp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}

	respBodyRaw, err := io.ReadAll(rawResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response-body request: %w", err)
	}

	var errCode error
	var respCode int
	switch rawResp.StatusCode {
	case 200:
	case 404:
		errCode = ErrRecordNotFound
	case 400:
		errCode = ErrUnauthorized
		respCode, _ = strconv.Atoi(string(respBodyRaw))
	default:
		errCode = ErrInternal
	}

	if errCode != nil {
		msg := string(respBodyRaw)
		if respCode != 0 && errDescriptions[respCode] != "" {
			msg = fmt.Sprintf("%s - %s", respBodyRaw, errDescriptions[respCode])
		}

		if len(msg) > 1 {
			return nil, fmt.Errorf("%w: call to %v returned statuscode %v, resp: %s",
				errCode, requestURL, rawResp.StatusCode, msg)
		}

		return nil, fmt.Errorf("%w: call to %v returned statuscode %v",
			errCode, requestURL, rawResp.StatusCode)
	}

	return respBodyRaw, nil
}

var errDescriptions = map[int]string{
	6:  "JSON parse failure, likely due to badly-formed POST data",
	8:  "Invalid BSO, likely due to badly-formed POST data",
	13: "Invalid collection, likely invalid chars in collection name",
	14: "User has exceeded their storage quota",
	16: "Client is known to be incompatible with the server",
	17: "Server limit exceeded, likely due to too many items or too large a payload in a POST request",
}
