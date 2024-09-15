package syncclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/Mikescher/firefox-sync-client/x"
)

type CollectionName string

const (
	CollectionBookmarks CollectionName = "bookmarks"
	CollectionPasswords CollectionName = "passwords"
	CollectionForms     CollectionName = "forms"
	CollectionHistory   CollectionName = "history"
	CollectionTabs      CollectionName = "tabs"
	CollectionCrypto    CollectionName = "crypto"
	CollectionMeta      CollectionName = "meta"
)

type Collection struct {
	Name         CollectionName
	LastModified time.Time
	Count        int
	Usage        int64 // bytes
}

type CollectionsInfo map[CollectionName]x.UnixFloatTime
type CollectionsCounts map[CollectionName]int
type CollectionsUsage map[CollectionName]float64

// GetCollections method aggregates information about collections and returns list of Collection
func (f *Client) GetCollections(ctx context.Context, session FFSyncSession) ([]Collection, error) {
	collectionInfos, err := f.GetCollectionsInfo(ctx, session)
	if err != nil {
		return nil, err
	}

	collectionsCounts, err := f.GetCollectionsCounts(ctx, session)
	if err != nil {
		return nil, err
	}

	collectionsUsage, err := f.GetCollectionsUsage(ctx, session)
	if err != nil {
		return nil, err
	}

	collections := make([]Collection, 0, len(collectionInfos))
	for name, lastModified := range collectionInfos {
		count := collectionsCounts[name]
		usage := int64(collectionsUsage[name] * 1024)

		collections = append(collections, Collection{
			Name:         name,
			LastModified: time.Time(lastModified),
			Count:        count,
			Usage:        usage,
		})
	}

	return collections, nil
}

func (f *Client) GetCollectionsInfo(ctx context.Context, session FFSyncSession) (CollectionsInfo, error) {
	binResp, err := f.request(ctx, session, "GET", "/info/collections", nil)
	if err != nil {
		return nil, fmt.Errorf("failed getting collections info: %w", err)
	}

	var resp CollectionsInfo
	err = json.Unmarshal(binResp, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal collections info: %w", err)
	}

	return resp, nil
}

func (f *Client) GetCollectionsCounts(ctx context.Context, session FFSyncSession) (CollectionsCounts, error) {
	binResp, err := f.request(ctx, session, "GET", "/info/collection_counts", nil)
	if err != nil {
		return nil, fmt.Errorf("failed requesting collection counts: %w", err)
	}

	var resp CollectionsCounts
	err = json.Unmarshal(binResp, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal collection counts: %w", err)
	}

	return resp, nil
}

func (f *Client) GetCollectionsUsage(ctx context.Context, session FFSyncSession) (CollectionsUsage, error) {
	binResp, err := f.request(ctx, session, "GET", "/info/collection_usage", nil)
	if err != nil {
		return nil, fmt.Errorf("failed requesting collection usage: %w", err)
	}

	var resp CollectionsUsage
	err = json.Unmarshal(binResp, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal collection usage: %w", err)
	}

	return resp, nil
}

func (f *Client) DeleteCollection(ctx context.Context, session FFSyncSession, collection string) error {
	_, err := f.request(ctx, session, "DELETE", fmt.Sprintf("/storage/%s", url.PathEscape(collection)), nil)
	if err != nil {
		return fmt.Errorf("failed deleting collection: %w", err)
	}

	return nil
}
