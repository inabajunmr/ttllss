package key

import (
	"crypto/sha256"
)

func TranscriptHash(messages ...[]byte) []byte {

	var concat []byte
	for _, v := range messages {
		concat = append(concat, v...)
	}

	// TODO sha256 決め打ち
	a := sha256.Sum256(concat)
	b := a[:]
	return b
}
