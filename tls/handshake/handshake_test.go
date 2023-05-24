package handshake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
)

func TestHandshakeEncodeAndDecode(t *testing.T) {

	hs := NewHandshakeServerHello(ServerHelloHandshakeType, sampleServerHello())

	encoded := hs.Encode()
	printBytes(encoded)
	_, decoded := DecodeHandShake(encoded)

	if !reflect.DeepEqual(hs, decoded) {
		t.Fatalf("original: %+v decoded: %+v", encoded, decoded)
	}
}

func sampleServerHello() ServerHello {

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

	return NewServerHello(0x0303, random, []byte{0x00, 0x01, 0x02}, TLS_AES_128_GCM_SHA256, 0,
		[]Extension{supportedVersionsExtension, supportedGroupsExtension, keyShareExtension, signatureAlgorithmsExtension})
}

func printBytes(bytes []byte) {
	for _, v := range bytes {
		fmt.Printf("%.2x ", v)
	}

	fmt.Println()
}
