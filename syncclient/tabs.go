package syncclient

import (
	"context"

	"github.com/Mikescher/firefox-sync-client/x"
)

func (c *Client) ListTabCollections(ctx context.Context, session FFSyncSession, input ListInput) ([]TabCollection, error) {
	records, err := ListRecords[TabCollection](c, ctx, session, input)
	if err != nil {
		return nil, err
	}

	return decryptAll(records, session)
}

type TabCollection struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted,omitempty"`
	Name    string `json:"clientName"`
	Tabs    []Tab  `json:"tabs"`
}

func (TabCollection) Collection() string {
	return "tabs"
}

type Tab struct {
	Title      string     `json:"title"`
	UrlHistory []string   `json:"urlHistory"`
	Icon       string     `json:"icon"`
	LastUsed   x.UnixTime `json:"lastUsed"`
}
