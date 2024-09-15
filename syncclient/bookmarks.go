package syncclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mikescher/firefox-sync-client/x"
)

type BookmarkType string

const (
	BookmarkTypeBookmark     BookmarkType = "bookmark"
	BookmarkTypeMicroSummary BookmarkType = "microsummary"
	BookmarkTypeQuery        BookmarkType = "query"
	BookmarkTypeFolder       BookmarkType = "folder"
	BookmarkTypeLivemark     BookmarkType = "livemark"
	BookmarkTypeSeparator    BookmarkType = "separator"
)

type bookmarkCommon struct {
	ID         string       `json:"id"`         // [common]
	Type       BookmarkType `json:"type"`       // [common]
	DateAdded  x.UnixTime   `json:"dateAdded"`  // [common]
	ParentID   string       `json:"parentid"`   // [common]
	ParentName string       `json:"parentName"` // [common]
}

func (b *bookmarkCommon) ApplyDefaults(id string) {
	b.ID = id

	if b.DateAdded.Time().IsZero() {
		b.DateAdded = x.UnixTime(time.Now())
	}
}

func (*bookmarkCommon) Collection() CollectionName {
	return "bookmarks"
}

type Bookmark struct {
	bookmarkCommon

	Title         string   `json:"title,omitempty"`         // [bookmark, microsummary, query, livemark, folder]
	URI           string   `json:"bmkUri,omitempty"`        // [bookmark, microsummary, query]
	Description   string   `json:"description,omitempty"`   // [bookmark, microsummary, query]
	LoadInSidebar bool     `json:"loadInSidebar,omitempty"` // [bookmark, microsummary, query]
	Tags          []string `json:"tags,omitempty"`          // [bookmark, microsummary, query]
	Keyword       string   `json:"keyword,omitempty"`       // [bookmark, microsummary, query]
	Deleted       bool     `json:"deleted"`

	Position *int `json:"-"`
}

func (f *Bookmark) ApplyDefaults(id string) {
	f.bookmarkCommon.ApplyDefaults(id)
	f.Type = BookmarkTypeBookmark
}

type Separator struct {
	bookmarkCommon

	SeparatorPosition int `json:"pos,omitempty"` // [separator]
}

func (f *Separator) ApplyDefaults(id string) {
	f.bookmarkCommon.ApplyDefaults(id)
	f.Type = BookmarkTypeSeparator
}

type Folder struct {
	bookmarkCommon

	Title    string   `json:"title,omitempty"`    // [bookmark, microsummary, query, livemark, folder]
	Children []string `json:"children,omitempty"` // [folder, livemark]
}

func (f *Folder) ApplyDefaults(id string) {
	f.bookmarkCommon.ApplyDefaults(id)
	f.Type = BookmarkTypeFolder
}

// CreateBookmark creates a new bookmark with the given input and position.
// It returns the ID of the newly created bookmark or an error if the operation fails.
func (c *Client) CreateBookmark(ctx context.Context, session FFSyncSession, input Bookmark) (string, error) {
	bookmark := NewRecord(input)

	position := -1
	if input.Position != nil {
		position = *input.Position
	}

	parent, _, err := calculateParent(c, ctx, session, bookmark, input.ParentID, position)
	if err != nil {
		return "", fmt.Errorf("failed to find+calculate parent: %w", err)
	}

	bookmark.Data.ParentID = parent.ID
	bookmark.Data.ParentName = parent.Data.Title

	encBookmark, err := bookmark.Encrypt(session)
	if err != nil {
		return "", err
	}

	err = PutRecord(c, ctx, session, encBookmark)
	if err != nil {
		return "", err
	}

	debug("[3] Update parent record")

	encParent, err := parent.Encrypt(session)
	if err != nil {
		return "", err
	}

	err = PutRecord(c, ctx, session, encParent)
	if err != nil {
		return "", err
	}

	return bookmark.ID, nil
}

// UpdateBookmark updates an existing bookmark
func (c *Client) UpdateBookmark(ctx context.Context, session FFSyncSession, input Bookmark) error {
	record, err := GetRecord[Bookmark](c, ctx, session, input.ID)
	if err != nil {
		return fmt.Errorf("failed to get bookmark: %w", err)
	}

	decryptedRecord, err := record.Decrypt(session)
	if err != nil {
		return fmt.Errorf("failed to decrypt bookmark: %w", err)
	}

	// Update the bookmark data
	decryptedRecord.Data = input

	// Encrypt and update the bookmark record
	updatedRecord, err := decryptedRecord.Encrypt(session)
	if err != nil {
		return fmt.Errorf("failed to encrypt updated bookmark: %w", err)
	}

	err = PutRecord(c, ctx, session, updatedRecord)
	if err != nil {
		return fmt.Errorf("failed to update bookmark record: %w", err)
	}

	// Handle position and parent update if necessary
	if input.Position != nil && input.ParentID != "" {
		parent, _, err := calculateParent[Bookmark](c, ctx, session, decryptedRecord, input.ParentID, *input.Position)
		if err != nil {
			return fmt.Errorf("failed to calculate parent: %w", err)
		}

		decryptedRecord.Data.ParentID = parent.ID
		decryptedRecord.Data.ParentName = parent.Data.Title

		// Update the parent record
		encParent, err := parent.Encrypt(session)
		if err != nil {
			return fmt.Errorf("failed to encrypt parent: %w", err)
		}

		err = PutRecord(c, ctx, session, encParent)
		if err != nil {
			return fmt.Errorf("failed to update parent record: %w", err)
		}
	}

	return nil
}

// DeleteBookmark deletes a bookmark by its ID
func (c *Client) DeleteBookmark(ctx context.Context, session FFSyncSession, id string) error {
	// First, get the bookmark record
	record, err := GetRecord[Bookmark](c, ctx, session, id)
	if err != nil {
		return fmt.Errorf("failed to get bookmark: %w", err)
	}

	// Decrypt the record to access the bookmark data
	decryptedRecord, err := record.Decrypt(session)
	if err != nil {
		return fmt.Errorf("failed to decrypt bookmark record: %w", err)
	}

	// Soft delete the bookmark by marking it as deleted
	decryptedRecord.Data.Deleted = true

	// Encrypt and update the record
	updatedRecord, err := decryptedRecord.Encrypt(session)
	if err != nil {
		return fmt.Errorf("failed to encrypt updated bookmark record: %w", err)
	}

	err = PutRecord(c, ctx, session, updatedRecord)
	if err != nil {
		return fmt.Errorf("failed to update bookmark record: %w", err)
	}

	// If the bookmark has a parent, update the parent's children list
	if decryptedRecord.Data.ParentID != "" {
		parentRecord, err := GetRecord[Folder](c, ctx, session, decryptedRecord.Data.ParentID)
		if err != nil {
			return fmt.Errorf("failed to get parent folder: %w", err)
		}

		decryptedParent, err := parentRecord.Decrypt(session)
		if err != nil {
			return fmt.Errorf("failed to decrypt parent folder record: %w", err)
		}

		// Remove the deleted bookmark from the parent's children
		newChildren := make([]string, 0, len(decryptedParent.Data.Children))
		for _, child := range decryptedParent.Data.Children {
			if child != id {
				newChildren = append(newChildren, child)
			}
		}
		decryptedParent.Data.Children = newChildren

		updatedParent, err := decryptedParent.Encrypt(session)
		if err != nil {
			return fmt.Errorf("failed to encrypt updated parent folder record: %w", err)
		}

		err = PutRecord(c, ctx, session, updatedParent)
		if err != nil {
			return fmt.Errorf("failed to update parent folder record: %w", err)
		}
	}

	return nil
}

// ListBookmarks retrieves a list of bookmarks based on the provided input.
// It decrypts each record and returns a slice of Bookmark structs.
func (c *Client) ListBookmarks(ctx context.Context, session FFSyncSession, input ListInput) ([]Bookmark, error) {
	records, err := ListRecords[Bookmark](c, ctx, session, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list bookmark records: %w", err)
	}

	return decryptAll(records, session)
}

// CreateFolder creates a new bookmark folder
func (c *Client) CreateFolder(ctx context.Context, session FFSyncSession, folder Folder) (string, error) {
	record := NewRecord(folder)

	encRecord, err := record.Encrypt(session)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt folder record: %w", err)
	}

	err = PutRecord(c, ctx, session, encRecord)
	if err != nil {
		return "", fmt.Errorf("failed to create folder: %w", err)
	}

	return folder.ID, nil
}

func calculateParent[T any](c *Client, ctx context.Context, session FFSyncSession, newRecord Record[T], parendID string, pos int) (Record[Folder], int, error) {
	debug("Query parent by ID", "newID", newRecord.ID, "parentID", parendID)

	rawRecord, err := GetRecord[Folder](c, ctx, session, parendID)
	if errors.Is(err, ErrRecordNotFound) {
		return Record[Folder]{}, 0, fmt.Errorf("parent-record with ID '%s' not found: %w", parendID, err)
	} else if err != nil {
		return Record[Folder]{}, 0, fmt.Errorf("failed to query parent-record: %w", err)
	}

	record, err := rawRecord.Decrypt(session)
	if err != nil {
		return Record[Folder]{}, 0, fmt.Errorf("failed to decode bookmark-record: %w", err)
	}

	record, normPos, err := moveChild(record, newRecord.ID, pos)
	if err != nil {
		return Record[Folder]{}, 0, fmt.Errorf("failed to move child: %w", err)
	}

	return record, normPos, nil
}

func moveChild(bmRec Record[Folder], recordID string, pos int) (Record[Folder], int, error) {
	children := make([]string, 0, len(bmRec.Data.Children))
	for _, v := range bmRec.Data.Children {
		if v != recordID {
			children = append(children, v)
		}
	}

	normPos := pos

	if normPos < 0 {
		normPos = len(children) + normPos + 1
	}

	debug("Movind child",
		"Position", pos,
		"Parent<old>.children.len", len(bmRec.Data.Children),
		"Position-normalized", normPos,
		"Parent<old>.children", strings.Join(bmRec.Data.Children, ", "))

	if normPos == len(children) {
		children = append(children, recordID)
	} else if 0 <= normPos && normPos < len(children) {
		children = append(children[:normPos+1], children[normPos:]...)
		children[normPos] = recordID
	} else {
		return Record[Folder]{}, 0,
			fmt.Errorf("%w: parent record [%d..%d] does not have an index %d (%d)", ErrValidation, 0, len(children), pos, normPos)
	}

	debug("Parent<new>.children", "children", children)

	bmRec.Data.Children = children

	return bmRec, normPos, nil
}
