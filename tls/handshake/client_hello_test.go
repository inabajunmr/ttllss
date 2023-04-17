package handshake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestClientHelloEncodeAndDecode(t *testing.T) {
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
