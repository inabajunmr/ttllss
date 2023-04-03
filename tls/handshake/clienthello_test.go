package handshake

import (
	"reflect"
	"testing"
)

func TestEncodeAndDecode(t *testing.T) {
	cipherSuites := []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384}
	supportedVersionsExtensions := NewSupportedVersionsForClient(
		[]ProtocolVersion{NewProtocolVersion(0x0304)},
	)
	ch := NewClientHello(cipherSuites, []Extension{supportedVersionsExtensions})

	encoded := ch.Encode()

	decoded := DecodeClientHello(encoded)

	if ch.legacyVersion != decoded.legacyVersion {
		t.Fatalf("legacyVersion original:%x decoded:%x", ch.legacyVersion, decoded.legacyVersion)
	}

	if ch.random != decoded.random {
		t.Fatalf("random original:%x decoded:%x", ch.random, decoded.random)
	}

	if !reflect.DeepEqual(ch.legacySessionId, decoded.legacySessionId) {
		t.Fatalf("legacySessionId original:%x decoded:%x", ch.legacySessionId, decoded.legacySessionId)
	}

	if !reflect.DeepEqual(ch.cipherSuites, decoded.cipherSuites) {
		t.Fatalf("legacySessionId original:%x decoded:%x", ch.cipherSuites, decoded.cipherSuites)
	}

	// t.Fatalf("%v\n%v", ch, decoded)

}
