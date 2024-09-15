package syncclient

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const FFSCLIENT_VERSION = "1.8.0"

type loginRequestSchema struct {
	Email  string `json:"email"`
	AuthPW string `json:"authPW"`
	Reason string `json:"reason"`
}

type loginResponseSchema struct {
	UserID             string `json:"uid"`
	SessionToken       string `json:"sessionToken"`
	AuthAt             int64  `json:"authAt"`
	MetricsEnabled     bool   `json:"metricsEnabled"`
	KeyFetchToken      string `json:"keyFetchToken"`
	Verified           bool   `json:"verified"`
	VerificationMethod string `json:"verificationMethod"`
}

type totpVerifyRequestSchema struct {
	Code    string `json:"code"`
	Service string `json:"service"`
}

type totpVerifyResponseSchema struct {
	Success bool `json:"success"`
}

func (f *Client) Login(ctx context.Context, email string, password string) (LoginSession, SessionVerification, error) {
	resp, stretchpwd, err := f.makeLoginRequest(ctx, email, password, stretchPassword(email, password), false)
	if err != nil {
		return LoginSession{}, "", err
	}

	kft, err := hex.DecodeString(resp.KeyFetchToken)
	if err != nil {
		return LoginSession{}, "", fmt.Errorf("failed to read KeyFetchToken: %w", err)
	}

	st, err := hex.DecodeString(resp.SessionToken)
	if err != nil {
		return LoginSession{}, "", fmt.Errorf("failed to read SessionToken: %w", err)
	}

	// printKV("UserID", resp.UserID)
	// printKV("SessionToken", st)
	// printKV("KeyFetchToken", kft)

	if !resp.Verified {
		switch resp.VerificationMethod {
		case "totp-2fa":
			return LoginSession{
				Mail:            email,
				StretchPassword: stretchpwd,
				UserId:          resp.UserID,
				SessionToken:    st,
				KeyFetchToken:   kft,
			}, VerificationTOTP2FA, nil
		case "email-2fa":
			return LoginSession{
				Mail:            email,
				StretchPassword: stretchpwd,
				UserId:          resp.UserID,
				SessionToken:    st,
				KeyFetchToken:   kft,
			}, VerificationMail2FA, nil
		case "email-otp":
			fallthrough
		case "email":
			return LoginSession{}, "",
				fmt.Errorf("%w: verify the login attempt (per e-mail) before continuing", ErrVerifyLogin)
		case "email-captcha":
			return LoginSession{}, "",
				fmt.Errorf("%w: account was issued a captcha, please solve the captcha mail to your e-mail address first", ErrVerifyLogin)
		}

		return LoginSession{}, "", fmt.Errorf("%w: requested verification method '%s' is unknown", ErrInternal, resp.VerificationMethod)
	}

	return LoginSession{
		Mail:            email,
		StretchPassword: stretchpwd,
		UserId:          resp.UserID,
		SessionToken:    st,
		KeyFetchToken:   kft,
	}, VerificationNone, nil
}

func (f Client) makeLoginRequest(ctx context.Context, email string, password string, stretchpwd []byte, is120Retry bool) (loginResponseSchema, []byte, error) {
	authPW, err := deriveKey(stretchpwd, "authPW", 32)
	if err != nil {
		return loginResponseSchema{}, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	body := loginRequestSchema{
		Email:  email,
		AuthPW: hex.EncodeToString(authPW), //lowercase
		Reason: "login",
	}

	bytesBody, err := json.Marshal(body)
	if err != nil {
		return loginResponseSchema{}, nil, fmt.Errorf("failed to marshal body: %w", err)
	}

	requestURL := f.AuthURL + "/account/login?keys=true"

	req, err := http.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewBuffer(bytesBody))
	if err != nil {
		return loginResponseSchema{}, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("User-Agent", "Mozilla/5.0 (Mobile; Firefox Accounts; rv:1.0) firefox-sync-client/"+FFSCLIENT_VERSION+"golang/1.19")
	req.Header.Add("Accept", "*/*")

	rawResp, err := f.client().Do(req)
	if err != nil {
		return loginResponseSchema{}, nil, fmt.Errorf("failed to do request: %w", err)
	}

	respBodyRaw, err := io.ReadAll(rawResp.Body)
	if err != nil {
		return loginResponseSchema{}, nil, fmt.Errorf("failed to read response-body request: %w", err)
	}

	if rawResp.StatusCode != 200 {
		var errResp loginErrorResponseSchema
		err = json.Unmarshal(respBodyRaw, &errResp)
		if err != nil {
			return loginResponseSchema{}, nil, fmt.Errorf("failed to unmarshal error:\n%w", err)
		}

		// If the email used to stretch the password is different from sync server, the server throws a 400 error
		// with message "Incorrect email case". The response json contains the correct email for stretching the password
		if rawResp.StatusCode == 400 && errResp.ErrNo == 120 && !is120Retry {
			return f.makeLoginRequest(ctx, email, password, stretchPassword(errResp.Email, password), true)
		}

		if len(string(respBodyRaw)) > 1 {
			return loginResponseSchema{}, nil, fmt.Errorf("%w: call to /login returned statuscode %v\nBody:\n%v", ErrInternal, rawResp.StatusCode, string(respBodyRaw))
		}

		return loginResponseSchema{}, nil, fmt.Errorf("%w: call to /login returned statuscode %v", ErrInternal, rawResp.StatusCode)
	}

	var resp loginResponseSchema
	err = json.Unmarshal(respBodyRaw, &resp)
	if err != nil {
		return loginResponseSchema{}, nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return resp, stretchpwd, nil
}

func (f *Client) VerifyWithOTP(ctx context.Context, session LoginSession, otp string) error {
	body := totpVerifyRequestSchema{
		Code:    otp,
		Service: "login",
	}
	binResp, _, err := f.requestWithHawkToken(ctx, "POST", "/session/verify/totp", body, session.SessionToken, "sessionToken")
	if err != nil {
		return fmt.Errorf("failed to verify session with OTP: %w", err)
	}

	var resp totpVerifyResponseSchema
	err = json.Unmarshal(binResp, &resp)
	if err != nil {
		return fmt.Errorf("failed to unmarshal totp verify response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("%w: OTP '%s' was not accepted by the server", ErrInvalidToTP, otp)
	}

	return nil
}
