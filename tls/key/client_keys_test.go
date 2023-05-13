package key

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// https://www.rfc-editor.org/rfc/rfc8448.html#section-3

func Test(t *testing.T) {
	keys := ClientKeys{}

	clientHello, _ := hex.DecodeString("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001")
	serverHello, _ := hex.DecodeString("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304")

	// 3.  Simple 1-RTT Handshake
	// {client}  create an ephemeral x25519 key pair:
	clientPrivateKey, err := hex.DecodeString("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005")
	if err != nil {
		panic(err)
	}
	// 99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c
	clientPublicKey, _ := curve25519.X25519(clientPrivateKey, curve25519.Basepoint)
	fmt.Printf("clientPublicKey: %x\n", clientPublicKey)

	// {server}  create an ephemeral x25519 key pair:
	serverPrivateKey, err := hex.DecodeString("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e")
	if err != nil {
		panic(err)
	}
	// c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f
	serverPublicKey, _ := curve25519.X25519(serverPrivateKey, curve25519.Basepoint)
	fmt.Printf("serverPublicKey: %x\n", serverPublicKey)

	// X25519 key exchange
	sharedKey, _ := curve25519.X25519(clientPrivateKey, serverPublicKey)
	fmt.Printf("sharedKey: %x\n", sharedKey)

	// {client}  extract secret "early" (same as server early secret)
	// 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
	fmt.Printf("earlySecret: %x\n", keys.GetEarlySecret())

	// {client}  derive secret for handshake "tls13 derived":
	clientDeriveSecretForHandshake := DeriveSecret(keys.GetEarlySecret(), []byte("derived"), []byte{})
	// 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba
	fmt.Printf("clientDeriveSecretForHandshake: %x\n", clientDeriveSecretForHandshake)

	// {client}  extract secret "handshake" (same as server handshake secret)
	cilentExtractSecretHandshake := hkdf.Extract(sha256.New, sharedKey, clientDeriveSecretForHandshake)
	// 1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac
	fmt.Printf("cilentExtractSecretHandshake: %x\n", cilentExtractSecretHandshake)

	// {client}  derive secret "tls13 c hs traffic" (same as server)
	clientDeriveSecret := DeriveSecret(cilentExtractSecretHandshake, []byte("s hs traffic"), clientHello, serverHello)
	// b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38
	fmt.Printf("clientDeriveSecret: %x\n", clientDeriveSecret)

	// TODO ここまであってるので AEAD でメッセージを復号

	t.Fail()

}
