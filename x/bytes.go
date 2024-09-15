package x

import "fmt"

func BytesXOR(a []byte, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("bytes XOR length mismatch %d != %d", len(a), len(b))
	}

	r := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
		r[i] = a[i] ^ b[i]
	}

	return r, nil
}
