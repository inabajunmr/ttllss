package key

import "crypto/sha256"

func DeriveSecret(secret []byte, label []byte, messages ...[]byte) []byte {
	return HkdfExpandLabel(secret, label, TranscriptHash(messages...), uint16(sha256.New().Size()))
}
