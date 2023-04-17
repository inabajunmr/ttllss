package handshake

import (
	"reflect"
	"testing"
)

func TestKeyshareEncodeAndDecode(t *testing.T) {
	e := NewKeyShareEntry(X25519, []byte{0x01, 0x02, 0x03})
	encoded := e.Encode()
	_, decoded := DecodeKeyShareEntry(encoded)

	if !reflect.DeepEqual(e, decoded) {
		t.Fatalf("original: %+v decoded: %+v", e, decoded)
	}
}
