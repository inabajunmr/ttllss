package key

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

// HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
func HkdfExpandLabel(secret []byte, label []byte, context []byte, length uint16) []byte {
	//  struct {
	//      uint16 length = Length;
	//      opaque label<7..255> = "tls13 " + Label;
	//      opaque context<0..255> = Context;
	//  } HkdfLabel;
	var hkdfLabelStr []byte
	hkdfLabelStr = append(hkdfLabelStr, []byte("tls13 ")...)
	hkdfLabelStr = append(hkdfLabelStr, label...)
	hkdfLabel := NewHkdfLabel(length, hkdfLabelStr, context)

	// expand
	okm := make([]byte, length)
	hkdf.Expand(sha256.New, secret, hkdfLabel.Encode()).Read(okm)
	return okm
}
