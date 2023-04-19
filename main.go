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
	fmt.Println("====== CLIENT HELLO ======")
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

	buf := make([]byte, 2048)
	count, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(buf[:count]))

	fmt.Println("====== SERVER HELLO ======")

	remain, shRecord := record.DecodeTLSPlainText(buf[:count])
	// TODO buf[:count] にまとめて返されるメッセージも全部入ってるので、DecodeTLSPlainText で残りの bytes を返してあげて引き続きデコードを進める必要がある
	// Google の場合 ChangeCipherSpec が返ってきてその後暗号化された Certificate とかが返ってくる
	shHandShake := handshake.DecodeHandShake(shRecord.Fragment())

	fmt.Printf("%+v\n", hsch)
	fmt.Printf("%+v\n", shHandShake)

	fmt.Printf("--- SERVER RESPONSE START ---")
	printBytes(buf[:count])
	fmt.Printf("--- SERVER RESPONSE END ---")

	serverPubX, serverPubY := elliptic.Unmarshal(elliptic.P256(), shHandShake.ServerHello.GetKeyShareExtenson().KeyExchange)

	// TODO server hello が返ってくるので鍵を交換
	x, _ := curve.ScalarMult(serverPubX, serverPubY, privKey.D.Bytes())
	sharedKey := x.Bytes()
	printBytes(sharedKey)

	fmt.Println("====== CHANGE CIPHER SPEC ======")

	// TODO 本来は DecodeTLSPlainText でループして type で処理を分ける

	var ccRecord record.TLSPlainText
	remain, ccRecord = record.DecodeTLSPlainText(remain)
	if ccRecord.ContentType == record.ChangeChipherSpec {
		fmt.Println("Skip change cipher spec.")
	}

	fmt.Println("====== CERTIFICATE ======")
	var certificateRecord record.TLSPlainText
	printBytes(remain)
	remain, certificateRecord = record.DecodeTLSPlainText(remain)
	fmt.Printf("%+v", certificateRecord)
	// その後 TLSCiphertext で Certificate とかが来るはず
	// Application data で来るのでこれをいい感じにする

}

func printBytes(bytes []byte) {
	counta := 0
	fmt.Print("0000   ")

	for _, v := range bytes {
		fmt.Printf("%.2x ", v)
		counta++
		if counta == 16 {
			fmt.Println()
			counta = 0
			fmt.Print("0000   ")
		}
	}

	fmt.Println()
}
