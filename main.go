package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/hkdf"

	"github.com/inabajunmr/ttllss/tls/handshake"
	"github.com/inabajunmr/ttllss/tls/key"
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

	fmt.Printf("--- DERIVE SERVER HANDSHAKE TRAFFIC SECRET START ---")
	// 0
	// |
	// v
	// PSK ->  HKDF-Extract = Early Secret
	hash := sha256.New
	earlySecret := hkdf.Extract(hash, []byte{}, []byte{})
	// |
	// v
	// Derive-Secret(., "derived", "")
	handshakeSecretInput := key.DeriveSecret(earlySecret, []byte("derived"), []byte{})
	// |
	// v
	// (EC)DHE -> HKDF-Extract = Handshake Secret
	handShakeSecret := hkdf.Extract(hash, sharedKey, handshakeSecretInput)
	// +-----> Derive-Secret(., "s hs traffic",
	// |                     ClientHello...ServerHello)
	// |                     = server_handshake_traffic_secret
	serverHandshakeTrafficSecret := key.DeriveSecret(handShakeSecret, []byte("s hs traffic"), hsch.Encode(), shRecord.Fragment())
	fmt.Println(serverHandshakeTrafficSecret)

	fmt.Println("--- DERIVE SERVER HANDSHAKE TRAFFIC SECRET END ---")

	fmt.Println("====== CHANGE CIPHER SPEC ======")

	// TODO 本来は DecodeTLSPlainText でループして type で処理を分ける

	var ccRecord record.TLSPlainText
	remain, ccRecord = record.DecodeTLSPlainText(remain)
	if ccRecord.ContentType == record.ChangeChipherSpec {
		fmt.Println("Skip change cipher spec.")
	}

	fmt.Println("====== CERTIFICATE ======")
	var certificateRecord record.TLSCiphertext
	printBytes(remain)
	remain, certificateRecord = record.DecodeTLSCiphertext(remain)
	// ここまではあってる
	printBytes(certificateRecord.EncryptedRecord)

	// AEAD で復号
	// AdditionalData
	{
		additioanlData := certificateRecord.AdditionalData()
	}

	// Nonce
	{
		// https://zenn.dev/0a24/articles/tls1_3-rfc8448
		// シーケンス番号は このタイミングで 0 でいいのか？（CipherText の送信が1つ目？
		// the first record transmitted under a particular traffic key MUST use sequence number 0.
		// https://datatracker.ietf.org/doc/html/rfc5116#section-5.3
		var secNumber uint64
		secNumber = 0
		// https://datatracker.ietf.org/doc/html/rfc5116#section-5.3
		ivLength := 12
		// 1.  The 64-bit record sequence number is encoded in network byte
		// order and padded to the left with zeros to iv_length.
		seqNumBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(seqNumBytes, secNumber)
		paddedSeqNumBytes := make([]byte, ivLength)
		copy(paddedSeqNumBytes[ivLength-len(seqNumBytes):], seqNumBytes)

		// 2.  The padded sequence number is XORed with either the static
		// client_write_iv or server_write_iv (depending on the role).
		// XOR the padded sequence number with the appropriate write IV
		var writeIV []byte
		// TODO writeIV の計算
		for i := 0; i < ivLength; i++ {
			paddedSeqNumBytes[i] ^= writeIV[i]
		}
	}

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
