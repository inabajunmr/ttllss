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
	keyShareExtension := KeyShareServerHello{serverShare: KeyShareEntry{group: Secp256r1, keyExchange: keyShareBytes}}

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

// sample from server
// 0000   16 03 03 00 80 02 00 00 7c 03 03 f2 13 28 98 38
// 0010   f5 76 bd 17 6a e1 57 82 53 76 84 21 9c bc 90 ed
// 0020   bb 45 41 aa fa 5b ef 5a d1 f8 7f 20 ab 02 4f 1c
// 0030   68 5a 45 97 6d 1e 51 bd bb 49 67 0a 7e ad ae 06
// 0040   34 b3 5b 3e 63 f8 0c dc 16 a1 f4 4e 13 01 00 00
// 0050   34 00 29 00 02 00 00 00 33 00 24 00 1d 00 20 74
// 0060   35 4c 21 97 4b 3e 2b 18 f0 4e 93 27 7f df 31 69
// 0070   2f f1 b5 8d 45 29 d5 f0 d3 96 e0 c2 b8 1d 07 00
// 0080   2b 00 02 03 04 14 03 03 00 01 01 17 03 03 00 e8
// 0090   fb be c1 03 d8 42 cd ff 85 b8 a1 a9 99 3b 17 60
// 00a0   e9 9c 69 ba be 9b 6e 71 4e f9 6f 21 27 5a 58 23
// 00b0   df b2 5e 9b d5 62 41 a6 52 64 09 57 ae 5d 1c 6a
// 00c0   07 72 5d 40 88 b5 2d 91 25 4f 23 f5 15 e5 6a f6
// 00d0   39 b2 dc 3e 3c e1 93 74 74 14 85 58 22 e8 63 84
// 00e0   d4 34 64 e9 c5 73 4d 5f b0 62 72 69 10 a9 d5 c8
// 00f0   99 f4 5b 09 fe 5c 40 9c 43 f5 9a c0 71 aa 19 6d
// 0100   48 74 7b 88 ef fd 70 55 9b 2d b0 e7 6a 98 aa 6a
// 0110   8b 38 05 9b 50 27 1e c5 8f dc 6f bf 00 53 08 9c
// 0120   bc 34 8a bd 12 40 ef 36 e2 3b 13 07 2b 15 b8 de
// 0130   17 45 02 6f ca ce c5 71 94 de 45 a1 96 29 d8 f4
// 0140   a5 56 b9 d1 d7 d9 ab d2 41 5f f0 6d 51 e3 17 88
// 0150   67 18 69 cf 6f 0a fc 24 2b 9b f2 43 c9 32 50 ba
// 0160   ec cf f3 f8 60 78 0e 5b 79 4f 55 7b 6e e1 26 41
// 0170   ba d8 06 d3 57 58 a7 1a

// TODO
