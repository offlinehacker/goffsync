package syncclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Mikescher/firefox-sync-client/x"
)

type keysResponseSchema struct {
	Bundle string `json:"bundle"`
}

func (f *Client) FetchKeys(ctx context.Context, session LoginSession) ([]byte, []byte, error) {
	binResp, hawkBundleKey, err := f.requestWithHawkToken(ctx, "GET", "/account/keys", nil, session.KeyFetchToken, "keyFetchToken")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query account keys: %w", err)
	}

	var resp keysResponseSchema
	err = json.Unmarshal(binResp, &resp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	//printKV("Bundle", resp.Bundle)

	bundle, err := hex.DecodeString(resp.Bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode Bundle: %w", err)
	}

	keys, err := unbundle("account/keys", hawkBundleKey, bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unbundle: %w", err)
	}

	//printKV("Keys<unbundled>", keys)

	unwrapKey, err := deriveKey(session.StretchPassword, "unwrapBkey", 32)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive-key: %w", err)
	}

	//printKV("Keys<unwrapped>", unwrapKey)

	kLow := keys[:32]
	kHigh := keys[32:]

	keyA := kLow
	keyB, err := x.BytesXOR(kHigh, unwrapKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to xor key-b: %w", err)
	}

	return keyA, keyB, nil
}
