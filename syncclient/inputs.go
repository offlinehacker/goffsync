package syncclient

import "time"

type ListInput struct {
	After  time.Time
	Sort   string
	Limit  int
	Offset int
	IDOnly bool
}
