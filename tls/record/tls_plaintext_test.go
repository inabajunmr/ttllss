package record

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/inabajunmr/ttllss/tls/handshake"
)

func TestEncodeAndDecode(t *testing.T) {

	cipherSuites := []handshake.CipherSuite{handshake.TLS_AES_128_GCM_SHA256}
	supportedVersionsExtension := handshake.NewSupportedVersionsForClient(
		[]handshake.ProtocolVersion{0x0304},
	)

	supportedGroupsExtension := handshake.NewSupportedGroupsExtention([]handshake.NamedGroup{handshake.Secp256r1})

	var clientShares []handshake.KeyShareEntry
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	pubKey := privKey.PublicKey
	keyShareBytes := elliptic.Marshal(curve, pubKey.X, pubKey.Y)
	clientShares = append(clientShares, handshake.NewKeyShareEntry(handshake.Secp256r1, keyShareBytes))
	keyShareExtension := handshake.NewKeyShareClientHello(clientShares)

	ch := handshake.NewClientHello(cipherSuites, []handshake.Extension{supportedVersionsExtension, supportedGroupsExtension, keyShareExtension})
	re := NewTLSPlainText(HandShake, ch.Encode())

	encoded := re.Encode()
	decoded := DecodeTLSPlainText(encoded)

	if re.contentType != decoded.contentType {
		t.Fatalf("contentType original:%v decoded:%v", re.contentType, decoded.contentType)
	}
	if re.legacyRecordVersion != decoded.legacyRecordVersion {
		t.Fatalf("legacyRecordVersion original:%v decoded:%v", re.legacyRecordVersion, decoded.legacyRecordVersion)
	}
	if re.length != decoded.length {
		t.Fatalf("length original:%v decoded:%v", re.length, decoded.length)
	}
	if !reflect.DeepEqual(re.fragment, decoded.fragment) {
		t.Fatalf("fragment original:%x decoded:%x", re.fragment, decoded.fragment)
	}
}
