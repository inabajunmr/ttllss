package handshake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestEncodeAndDecode(t *testing.T) {
	cipherSuites := []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384}

	// extensions
	// supported_versions
	supportedVersionsExtension := NewSupportedVersionsForClient(
		[]ProtocolVersion{0x0304},
	)

	// supported_groups
	supportedGroupsExtension := NewSupportedGroupsExtention([]NamedGroup{Secp256r1, X25519})

	// key_share
	var clientShares []KeyShareEntry
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	pubKey := privKey.PublicKey
	keyShareBytes := elliptic.Marshal(curve, pubKey.X, pubKey.Y)
	clientShares = append(clientShares, KeyShareEntry{group: Secp256r1, keyExchange: keyShareBytes})
	keyShareExtension := KeyShareClientHello{clientShares: clientShares}

	// signature_algorithms
	var signatureAlgorithms []SignatureScheme
	signatureAlgorithms = append(signatureAlgorithms, EcdsaSecp256r1Sha256)
	signatureAlgorithmsExtension := NewSignatureAlgorithmExtention(signatureAlgorithms)
	ch := NewClientHello(cipherSuites, []Extension{supportedVersionsExtension, supportedGroupsExtension, keyShareExtension, signatureAlgorithmsExtension})

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

	if !reflect.DeepEqual(ch.legacyCompressionMethods, decoded.legacyCompressionMethods) {
		t.Fatalf("legacyCompressionMethods original:%x decoded:%x", ch.legacyCompressionMethods, decoded.legacyCompressionMethods)
	}

	if !reflect.DeepEqual(ch.extensions, decoded.extensions) {
		t.Fatalf("extensions original:%x decoded:%x", ch.extensions, decoded.extensions)
	}
}

func Test2(t *testing.T) {
	// https://github.com/shiguredo/tls13-zig/blob/develop/src/client_hello.zig
	a := []byte{
		0x03, 0x03, 0xf0 /* version */, 0x5d, 0x41, 0x2d, 0x24, 0x35, 0x27, 0xfd, 0x90, 0xb5, 0xb4,
		0x24, 0x9d, 0x4a, 0x69, 0xf8, 0x97, 0xb5, 0xcf, 0xfe, 0xe3, 0x8d, 0x4c, 0xec,
		0xc7, 0x8f, 0xd0, 0x25, 0xc6, 0xeb, 0xe1, 0x33 /* random */, 0x20, 0x67, 0x7e, 0xb6, 0x52,
		0xad, 0x12, 0x51, 0xda, 0x7a, 0xe4, 0x5d, 0x3f, 0x19, 0x2c, 0xd1, 0xbf, 0xaf,
		0xca, 0xa8, 0xc5, 0xfe, 0x59, 0x2f, 0x1b, 0x2f, 0x2a, 0x96, 0x1e, 0x12, 0x83,
		0x35, 0xae /* legacySessionId */, 0x00, 0x02, 0x13, 0x02, 0x01, 0x00, 0x00 /* cipherSuites */, 0x45 /* legacyCompressionMethods */, 0x00, 0x2b, 0x00,
		0x03, 0x02, 0x03, 0x04 /** supported versions */, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00,
		0x17 /** supported groups */, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x49, 0x51,
		0x50, 0xa9, 0x0a, 0x47, 0x82, 0xfe, 0xa7, 0x47, 0xf5, 0xcb, 0x55, 0x19, 0xdc,
		0xf0, 0xce, 0x0d, 0xee, 0x9c, 0xdc, 0x04, 0x93, 0xbd, 0x84, 0x9e, 0xea, 0xf7,
		0xd3, 0x93, 0x64, 0x2f, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08,
		0x07,
	}
	c := DecodeClientHello(a)
	t.Fatalf("%+v", c)
}
