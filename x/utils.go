package x

import (
	"crypto/rand"
	"math"
	"math/big"
	"time"
)

var (
	base62CharacterSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func RandBase62(rlen int) string {
	bi52 := big.NewInt(int64(len(base62CharacterSet)))

	randMax := big.NewInt(math.MaxInt64)

	r := ""

	for i := 0; i < rlen; i++ {
		v, err := rand.Int(rand.Reader, randMax)
		if err != nil {
			panic(err)
		}

		r += string(base62CharacterSet[v.Mod(v, bi52).Int64()])
	}

	return r
}

func Ternary[T any](cond bool, v1 T, v2 T) T {
	if cond {
		return v1
	}

	return v2
}

// MinTime returns the earlier of two given times
func MinTime(t1, t2 time.Time) time.Time {
	if t1.Before(t2) {
		return t1
	}
	return t2
}
