package syncclient

import "errors"

var (
	ErrRecordExists   = errors.New("record already exists")
	ErrUnmarshal      = errors.New("unmarshal error")
	ErrValidation     = errors.New("validation error")
	ErrRequestFailed  = errors.New("request failed")
	ErrRecordNotFound = errors.New("request failed: record not found")
	ErrUnauthorized   = errors.New("request failed: unauthorized")
	ErrInternal       = errors.New("request failed: internal")
	ErrVerifyLogin    = errors.New("verify login attempt")
	ErrInvalidToTP    = errors.New("invalid totp")
)
