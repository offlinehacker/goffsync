package syncclient

import (
	"context"
	"encoding/json"
	"fmt"
)

type SessionState string

const (
	SessionStateVerified SessionState = "verified"
)

type SessionStatus struct {
	State  SessionState `json:"state"`
	UserID string       `json:"uid"`
}

func (s *SessionStatus) IsVerified(userID string) bool {
	return s.UserID == userID && s.State == SessionStateVerified
}

func (f *Client) GetSessionStatus(ctx context.Context, session FFSyncSession) (SessionStatus, error) {
	binResp, _, err := f.requestWithHawkToken(ctx, "GET", "/session/status", nil, session.SessionToken, "sessionToken")
	if err != nil {
		return SessionStatus{}, fmt.Errorf("API request failed: %w", err)
	}

	var resp SessionStatus
	err = json.Unmarshal(binResp, &resp)
	if err != nil {
		return SessionStatus{}, fmt.Errorf("failed to unmarshal session status: %w", err)
	}

	return resp, nil
}
