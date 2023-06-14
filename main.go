package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"

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

	keys := key.ClientKeys{}

	var clientShares []handshake.KeyShareEntry
	curve := elliptic.P256()
	keys.SetCurve(curve)
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	keys.SetClientPrivateKey(*privKey)
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
	_, shHandShake := handshake.DecodeHandShake(shRecord.Fragment())
	serverPubX, serverPubY := elliptic.Unmarshal(elliptic.P256(), shHandShake.ServerHello.GetKeyShareExtenson().KeyExchange)
	keys.SetServerPublicKey(serverPubX, serverPubY)

	fmt.Println("--- SERVER RESPONSE START ---")
	printBytes(buf[:count])
	fmt.Println("--- SERVER RESPONSE END ---")

	fmt.Println("--- DERIVE SERVER HANDSHAKE TRAFFIC SECRET START ---")
	serverHandshakeTrafficSecret := keys.GetServerHandshakeTrafficSecret(hsch.Encode(), shRecord.Fragment())
	fmt.Println("serverHandshakeTrafficSecret")
	printBytes(serverHandshakeTrafficSecret)
	fmt.Println("serverHandshakeTrafficSecret")
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
	var additionalData []byte
	{
		additionalData = certificateRecord.AdditionalData()
	}

	ivLength := 12

	// Nonce
	var nonce []byte
	{
		// https://zenn.dev/0a24/articles/tls1_3-rfc8448
		// シーケンス番号は このタイミングで 0 でいいのか？（CipherText の送信が1つ目？
		// the first record transmitted under a particular traffic key MUST use sequence number 0.
		// https://datatracker.ietf.org/doc/html/rfc5116#section-5.3
		var secNumber uint64
		secNumber = 0
		// https://datatracker.ietf.org/doc/html/rfc5116#section-5.3
		// 1.  The 64-bit record sequence number is encoded in network byte
		// order and padded to the left with zeros to iv_length.
		seqNumBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(seqNumBytes, secNumber)
		paddedSeqNumBytes := make([]byte, ivLength)
		copy(paddedSeqNumBytes[ivLength-len(seqNumBytes):], seqNumBytes)

		// 2.  The padded sequence number is XORed with either the static
		// client_write_iv or server_write_iv (depending on the role).
		// XOR the padded sequence number with the appropriate write IV
		// writeIV の計算 https://datatracker.ietf.org/doc/html/rfc8446#section-7.3
		// [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
		serverWriteIV := key.HkdfExpandLabel(serverHandshakeTrafficSecret, []byte("iv"), []byte(""), uint16(ivLength))

		for i := 0; i < ivLength; i++ {
			paddedSeqNumBytes[i] ^= serverWriteIV[i]
		}

		nonce = paddedSeqNumBytes
	}

	// serverWriteKey
	// https://datatracker.ietf.org/doc/html/rfc5116#section-5.1
	// K_LEN is 16 octets,
	kLength := 16
	serverWriteKey := key.HkdfExpandLabel(serverHandshakeTrafficSecret, []byte("key"), []byte(""), uint16(kLength))
	fmt.Println("serverWriteKey")
	printBytes(serverWriteKey)
	fmt.Println("serverWriteKey")

	// AEAD Decrypt
	// https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
	// plaintext of encrypted_record =
	//      AEAD-Decrypt(peer_write_key, nonce,
	// 			 additional_data, AEADEncrypted)
	decrypted, err := decrypt(certificateRecord.EncryptedRecord, nonce, additionalData, serverWriteKey)
	if err != nil {
		// TODO 認証で落ちてる
		// いろいろ適当なのでHKDF周りのテストから書いてく
		log.Fatal(err)

	}
	printBytes(decrypted)

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

func decrypt(cipherText, nonce, additionalData, key []byte) ([]byte, error) {
	// キーから新しい AES 暗号化ブロックを作成する
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// AEAD 暗号化ブロックを作成する
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 追加の認証データを使用して、認証タグを計算する
	tag := aead.Seal(nil, nonce, cipherText, additionalData)

	// 認証タグを cipherText の末尾に追加する
	cipherTextWithTag := append(cipherText, tag...)

	// 暗号文と認証タグから元のデータを復号化する
	plaintext, err := aead.Open(nil, nonce, cipherTextWithTag, additionalData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
