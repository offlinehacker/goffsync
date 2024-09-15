package syncclient

import (
	"fmt"
)

type APIError struct {
	Path       string
	Collection string
	ID         string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API request failed [collection=%s,id=%s]", e.Collection, e.ID)
}
