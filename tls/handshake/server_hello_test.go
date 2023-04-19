package handshake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
)

func TestServerHelloEncodeAndDecode(t *testing.T) {
	var random [32]byte
	rand.Read(random[:])

	// extensions
	// supported_versions
	supportedVersionsExtension := NewSupportedVersionsForServer(0x0304)

	// supported_groups
	supportedGroupsExtension := NewSupportedGroupsExtention([]NamedGroup{Secp256r1, X25519})

	// key_share
	curve := elliptic.P256()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	pubKey := privKey.PublicKey
	keyShareBytes := elliptic.Marshal(curve, pubKey.X, pubKey.Y)
	keyShareExtension := KeyShareServerHello{serverShare: KeyShareEntry{Group: Secp256r1, KeyExchange: keyShareBytes}}

	// signature_algorithms
	var signatureAlgorithms []SignatureScheme
	signatureAlgorithms = append(signatureAlgorithms, EcdsaSecp256r1Sha256)
	signatureAlgorithmsExtension := NewSignatureAlgorithmExtention(signatureAlgorithms)

	ch := NewServerHello(0x0303, random, []byte{0x00, 0x01, 0x02}, TLS_AES_128_GCM_SHA256, 0,
		[]Extension{supportedVersionsExtension, supportedGroupsExtension, keyShareExtension, signatureAlgorithmsExtension})

	encoded := ch.Encode()
	fmt.Printf("%x\n", encoded)
	decoded := DecodeServerHello(encoded)

	if ch.legacyVersion != decoded.legacyVersion {
		t.Fatalf("legacyVersion original:%x decoded:%x", ch.legacyVersion, decoded.legacyVersion)
	}

	if ch.random != decoded.random {
		t.Fatalf("random original:%x decoded:%x", ch.random, decoded.random)
	}

	if !reflect.DeepEqual(ch.legacySessionIdEcho, decoded.legacySessionIdEcho) {
		t.Fatalf("legacySessionIdEcho original:%x decoded:%x", ch.legacySessionIdEcho, decoded.legacySessionIdEcho)
	}

	if !reflect.DeepEqual(ch.cipherSuite, decoded.cipherSuite) {
		t.Fatalf("cipherSuite original:%x decoded:%x", ch.cipherSuite, decoded.cipherSuite)
	}

	if !reflect.DeepEqual(ch.legacyCompressionMethod, decoded.legacyCompressionMethod) {
		t.Fatalf("legacyCompressionMethod original:%x decoded:%x", ch.legacyCompressionMethod, decoded.legacyCompressionMethod)
	}

	if !reflect.DeepEqual(ch.extensions, decoded.extensions) {
		t.Fatalf("extensions original:%x\ndecoded:%x", ch.extensions, decoded.extensions)
	}
}
