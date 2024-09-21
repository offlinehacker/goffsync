package syncclient

import (
	"context"
	"testing"
)

func TestCreateBookmark(t *testing.T) {
	ctx := context.Background()

	client := New()

	session, verification, err := client.Login(ctx, LoginInput{
		Username: "test@example.com",
		Password: "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	bookmark := Bookmark{
		Title:         "Test",
		URI:           "https://example.com",
		Description:   "This is a test bookmark",
		LoadInSidebar: true,
		Tags:          []string{"test", "bookmark"},
		Keyword:       "test",
		Position:      &bookmarkPosition,
	}

	id, err := client.CreateBookmark(ctx, session, bookmark)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Created bookmark with ID", id)
}
