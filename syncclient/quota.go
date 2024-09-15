package syncclient

import (
	"context"
	"encoding/json"
	"fmt"
)

type Quota struct{ User, Total int64 }

func (q *Quota) Unmarshal(v []byte) error {
	var result [2]int64

	err := json.Unmarshal(v, &result)
	if err != nil {
		return err
	}

	q.User = result[0]
	q.Total = result[1]

	return nil
}

func (f *Client) GetQuota(ctx context.Context, session FFSyncSession) (Quota, error) {
	binResp, err := f.request(ctx, session, "GET", "/info/quota", nil)
	if err != nil {
		return Quota{}, fmt.Errorf("API request failed: %w", err)
	}

	var resp Quota
	err = json.Unmarshal(binResp, &resp)
	if err != nil {
		return resp, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return resp, nil
}
