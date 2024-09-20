package syncclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/Mikescher/firefox-sync-client/x"
)

type collectionGetter interface {
	Collection() CollectionName
}

type defaultApplyer interface {
	ApplyDefaults(ID string)
}

type recordPayload struct {
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"IV"`
	HMAC       string `json:"hmac"`
}

type RawRecord[T any] struct {
	ID        string                       `json:"id"`
	Modified  x.UnixFloatTime              `json:"modified"`
	Payload   *x.JSONString[recordPayload] `json:"payload,omitempty"`
	SortIndex *int64                       `json:"sortIndex,omitempty"`
	TTL       *int64                       `json:"ttl,omitempty"`
}

type Record[T any] struct {
	RawRecord[T]
	Data T `json:"-"`
}

func NewRecord[T any](data ...T) Record[T] {
	var val *T
	_ = any(val).(collectionGetter)

	var d T
	if len(data) > 0 {
		d = data[0]
	}

	id := newRecordID()

	if v, ok := any(d).(defaultApplyer); ok {
		v.ApplyDefaults(id)
	}

	return Record[T]{RawRecord: RawRecord[T]{ID: id}, Data: d}
}

func (RawRecord[T]) Collection() CollectionName {
	var v *T
	return any(v).(collectionGetter).Collection()
}

// Encode method encrypts payload and returns updated Record
func (r Record[T]) Encrypt(session FFSyncSession) (RawRecord[T], error) {
	collection := r.Collection()

	bulkKeys := session.BulkKeys[""]

	if v, ok := session.BulkKeys[string(collection)]; ok {
		debug("Use collection-specific bulk-keys")

		bulkKeys = v
	} else {
		debug("Use global bulk-keys")
	}

	debug("Encrypting payload",
		"EncryptionKey", bulkKeys.EncryptionKey,
		"HMACKey", bulkKeys.HMACKey,
	)

	plaintext, err := json.Marshal(r.Data)
	if err != nil {
		return RawRecord[T]{}, err
	}

	ciphertext, iv, hmac, err := encryptPayload(string(plaintext), bulkKeys)
	if err != nil {
		return RawRecord[T]{}, fmt.Errorf("failed to decrypt payload of record: %w", err)
	}

	r.Payload = &x.JSONString[recordPayload]{
		Value: recordPayload{
			Ciphertext: ciphertext,
			IV:         iv,
			HMAC:       hmac,
		},
	}

	return r.RawRecord, nil
}

func (r RawRecord[T]) Update(session FFSyncSession, input T) (RawRecord[T], error) {
	record, err := r.Decrypt(session)
	if err != nil {
		return r, err
	}

	record.Data = input

	return record.Encrypt(session)
}

func decryptAll[T any](records []RawRecord[T], session FFSyncSession) ([]T, error) {
	var result []T

	for _, r := range records {
		decrypted, err := r.Decrypt(session)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt %T record: %w", r, err)
		}

		result = append(result, decrypted.Data)
	}

	return result, nil
}

// Decode method decrypts and unmarshals Record payload
func (record RawRecord[T]) Decrypt(session FFSyncSession) (Record[T], error) {
	result := Record[T]{RawRecord: record}

	if record.Payload == nil {
		return result, fmt.Errorf("payload empty")
	}

	collection := any(&result).(collectionGetter).Collection()

	bulkKeys := session.BulkKeys[""]

	if v, ok := session.BulkKeys[string(collection)]; ok {
		debug("Use collection-specific bulk-keys")

		bulkKeys = v
	} else {
		debug("Use global bulk-keys")
	}

	debug("Decrypting payload",
		"EncryptionKey", bulkKeys.EncryptionKey,
		"HMACKey", bulkKeys.HMACKey)

	value := record.Payload.Value

	dplBin, err := decryptPayload(value.Ciphertext, value.IV, value.HMAC, bulkKeys)
	if err != nil {
		return result, fmt.Errorf("failed to decrypt record payload: %w", err)
	}

	var data T
	err = json.Unmarshal(dplBin, &data)
	if err != nil {
		return result, fmt.Errorf("failed unmarshaling payload: %w", err)
	}

	result.Data = data

	return result, nil
}

func GetRecord[T any](client *Client, ctx context.Context, session FFSyncSession, id string) (RawRecord[T], error) {
	var record RawRecord[T]

	collection := record.Collection()

	binResp, err := client.request(ctx, session, "GET", fmt.Sprintf("/storage/%s/%s", url.PathEscape(string(collection)), url.PathEscape(id)), nil)
	if err != nil {
		return record, fmt.Errorf("API request failed: %w", err)
	}

	err = json.Unmarshal(binResp, &record)
	if err != nil {
		return record, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return record, nil
}

func PutRecord[T any](client *Client, ctx context.Context, session FFSyncSession, record RawRecord[T]) error {
	collection := string(record.Collection())

	_, err := client.request(ctx, session, "PUT", fmt.Sprintf("/storage/%s/%s", url.PathEscape(collection), url.PathEscape(record.ID)), record)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}

	return nil
}

func ListRecords[T any](client *Client, ctx context.Context, session FFSyncSession, input ListInput) ([]RawRecord[T], error) {
	collection := (RawRecord[T]{}).Collection()

	requrl := fmt.Sprintf("/storage/%s", url.PathEscape(string(collection)))

	params := make([]string, 0, 8)

	if !input.After.IsZero() {
		params = append(params, "newer="+strconv.FormatInt(input.After.Unix(), 10))
	}
	if input.Sort != "" {
		params = append(params, "sort="+input.Sort)
	}
	if !input.IDOnly {
		params = append(params, "full=true")
	}
	if input.Limit != 0 {
		params = append(params, "limit="+strconv.Itoa(input.Limit))
	}
	if input.Offset != 0 {
		params = append(params, "offset="+strconv.Itoa(input.Offset))
	}

	if len(params) > 0 {
		requrl = requrl + "?" + strings.Join(params, "&")
	}

	binResp, err := client.request(ctx, session, "GET", requrl, nil)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	var result []RawRecord[T]

	if input.IDOnly {
		var resp listRecordsIDsResponseSchema
		err = json.Unmarshal(binResp, &resp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal response: %w", err)
		}

		for _, v := range resp {
			result = append(result, RawRecord[T]{ID: v})
		}

		return result, nil
	}

	err = json.Unmarshal(binResp, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response:\n%w", err)
	}

	return result, nil
}

func DeleteRecord[T any](client *Client, ctx context.Context, session FFSyncSession, record RawRecord[T]) error {
	collection := string(record.Collection())

	_, err := client.request(ctx, session, "DELETE", fmt.Sprintf("/storage/%s/%s", url.PathEscape(collection), url.PathEscape(record.ID)), nil)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}

	return nil
}

func RecordExists(client *Client, ctx context.Context, session FFSyncSession, collection, id string) (bool, error) {
	_, err := client.request(ctx, session, "GET", fmt.Sprintf("/storage/%s/%s", url.PathEscape(collection), url.PathEscape(id)), nil)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrRecordNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("API request failed: %w", err)
}

func newRecordID() string {
	// BSO ids must only contain printable ASCII characters. They should be exactly 12 base64-urlsafe characters
	// (we use base62, so we don't have to handle annoying special characters)
	return x.RandBase62(12)
}
