package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net"

	"github.com/inabajunmr/ttllss/tls/handshake"
	"github.com/inabajunmr/ttllss/tls/key"
	"github.com/inabajunmr/ttllss/tls/record"
	"golang.org/x/crypto/curve25519"
)

// TODO key パッケージを使って書き直していく
// TODO key パッケージ、アルゴリズムの採用範囲が狭いので注意
func main() {

	// prepare ClientHello
	fmt.Println("====== CLIENT HELLO ======")
	cipherSuites := []handshake.CipherSuite{handshake.TLS_AES_128_GCM_SHA256}
	supportedVersionsExtension := handshake.NewSupportedVersionsForClient(
		[]handshake.ProtocolVersion{0x0304},
	)

	supportedGroupsExtension := handshake.NewSupportedGroupsExtention([]handshake.NamedGroup{handshake.X25519})

	keys := key.ClientKeys{}

	var clientShares []handshake.KeyShareEntry

	privateKeyA := make([]byte, 32)
	_, err := rand.Read(privateKeyA)
	if err != nil {
		fmt.Println("プライベートキーの生成に失敗しました:", err)
		return
	}

	publicKeyA := make([]byte, 32)
	pub := (*[32]byte)(publicKeyA)
	pri := (*[32]byte)(privateKeyA)
	curve25519.ScalarBaseMult(pub, pri)

	fmt.Printf("\n■■■■■\npub %+x pri %+x\n", pub, pri)

	keys.SetCurve(elliptic.P256())

	keys.SetClientPrivateKey(privateKeyA)

	clientShares = append(clientShares, handshake.NewKeyShareEntry(handshake.X25519, publicKeyA))
	keyShareExtension := handshake.NewKeyShareClientHello(clientShares)

	ch := handshake.NewClientHello(cipherSuites, []handshake.Extension{supportedVersionsExtension, supportedGroupsExtension, keyShareExtension})
	hsch := handshake.NewHandshakeClientHello(handshake.ClientHelloHandshakeType, ch)

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
	keys.SetServerPublicKey(shHandShake.ServerHello.GetKeyShareExtenson().KeyExchange)

	// Change Cipher spec が邪魔？

	fmt.Println("====== Change Cihper Spec ======")
	var ccRecord record.TLSCiphertext
	remain, ccRecord = record.DecodeTLSCiphertext(remain)
	fmt.Printf("%+v\n", ccRecord)

	fmt.Println("======== Encrypted =========")
	var ccRecord2 record.TLSCiphertext
	remain, ccRecord2 = record.DecodeTLSCiphertext(remain)
	fmt.Printf("%+v\n", ccRecord2)

	fmt.Println("======== re =========") // あってそう
	printBytes(re.Fragment())
	fmt.Println("======== sh =========") // あってそう
	printBytes(shRecord.Fragment())

	// TODO 鍵交換がうまくいっていない気がする
	decrypted := keys.DecryptTLSCiphertext(ccRecord2.EncryptedRecord, re.Fragment(), shRecord.Fragment())

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
