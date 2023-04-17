package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net"

	"github.com/inabajunmr/ttllss/tls/handshake"
	"github.com/inabajunmr/ttllss/tls/record"
)

func main() {

	// prepare ClientHello
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
	hsch := handshake.NewHandshakeClientHello(1, ch)

	re := record.NewTLSPlainText(record.HandShake, hsch.Encode())
	printBytes(re.Encode())

	// send ClientHello
	conn, err := net.Dial("tcp", "google.com:443")
	fmt.Println(conn.RemoteAddr())
	if err != nil {
		log.Fatal(err)
	}

	_, err = conn.Write(re.Encode())
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1024)
	count, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(buf[:count]))

	shRecord := record.DecodeTLSPlainText(buf[:count])
	shHandShake := handshake.DecodeHandShake(shRecord.Fragment())

	fmt.Printf("%+v\n", hsch)
	fmt.Printf("%+v\n", shHandShake)

	// TODO server hello が返ってくるので鍵を交換
	// その後 TLSCiphertext で Certificate とかが来るはず
}

func printBytes(bytes []byte) {
	for _, v := range bytes {
		fmt.Printf("%.2x ", v)
	}

	fmt.Println()
}
