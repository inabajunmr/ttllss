package key

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/inabajunmr/ttllss/tls/handshake"
	"github.com/inabajunmr/ttllss/tls/record"
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
	serverHandshakeTrafficSecret := DeriveSecret(cilentExtractSecretHandshake, []byte("s hs traffic"), clientHello, serverHello)
	// b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38
	fmt.Printf("clientDeriveSecret: %x\n", serverHandshakeTrafficSecret)

	// TODO ===========
	// TODO ここまであってるので AEAD でメッセージを復号
	encryptedCertificateMessage, _ := hex.DecodeString("17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b")
	_, certificateRecord := record.DecodeTLSCiphertext(encryptedCertificateMessage)
	fmt.Printf("certificateRecord.EncryptedRecord: %x\n", certificateRecord.EncryptedRecord)

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
		serverWriteIV := HkdfExpandLabel(serverHandshakeTrafficSecret, []byte("iv"), []byte(""), uint16(ivLength))
		fmt.Println("serverWriteIV")
		// あってる 5d313eb2671276ee13000b30
		printBytes(serverWriteIV)
		fmt.Println("serverWriteIV")
		for i := 0; i < ivLength; i++ {
			paddedSeqNumBytes[i] ^= serverWriteIV[i]
		}

		nonce = paddedSeqNumBytes
	}

	// serverWriteKey
	// https://datatracker.ietf.org/doc/html/rfc5116#section-5.1
	// K_LEN is 16 octets,
	kLength := 16
	serverWriteKey := HkdfExpandLabel(serverHandshakeTrafficSecret, []byte("key"), []byte(""), uint16(kLength))
	// これはあってる 3fce516009c21727d0f2e4e86ee403bc
	fmt.Println("serverWriteKey")
	printBytes(serverWriteKey)
	fmt.Println("serverWriteKey")

	// AEAD Decrypt
	// https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
	// plaintext of encrypted_record =
	//      AEAD-Decrypt(peer_write_key, nonce,
	// 			 additional_data, AEADEncrypted)
	// TODO nonce か additionalData がおかしいらしい
	fmt.Println("additionalData")
	// なんとなくあってる気がする
	printBytes(additionalData)
	fmt.Println("additionalData")

	decrypted, err := decrypt(certificateRecord.EncryptedRecord, nonce, additionalData, serverWriteKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypted")
	printBytes(decrypted)
	fmt.Println("decrypted")

	remain, encryptedExtension := handshake.DecodeHandShake(decrypted)
	fmt.Printf("===== encryptedExtension ===== \n %+v\n", encryptedExtension)
	remain, certificate := handshake.DecodeHandShake(remain)
	fmt.Printf("===== certificate ===== \n %+v\n", certificate)
	// 証明書検証は多分サンプルなので無理
	// 最初の方に証明書の秘密鍵書いてあった
	remain, certificateVerify := handshake.DecodeHandShake(remain)
	fmt.Printf("===== certificateVerify ===== \n %+v\n", certificateVerify)
	// TODO ここの verify は書けるはず
	fmt.Printf("REMAIN %+v\n", remain)
	remain, finished := handshake.DecodeHandShake(remain)
	fmt.Printf("===== finished ===== \n  %+v\n", finished)
	printBytes(finished.Finished.VerifyData)

	// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
	// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
	// base key is serverHandshakeTrafficSecret at https://datatracker.ietf.org/doc/html/rfc8446#section-4.4
	// hash length は 16 じゃない
	//
	finishedKey := HkdfExpandLabel(serverHandshakeTrafficSecret, []byte("finished"), []byte(""), sha256.Size)
	fmt.Println("==== finished key ====")
	// これはあっている
	printBytes(finishedKey)

	// verify_data =
	// HMAC(finished_key,
	// 	 Transcript-Hash(Handshake Context,
	// 					 Certificate*, CertificateVerify*))
	hash := hmac.New(sha256.New, []byte(finishedKey))

	// メッセージをハッシュ関数に書き込む
	// TODO HMAC が一致しない
	// 多分エンコードで元の値に戻せてない気がする

	// エンコードした値じゃなくて　RFC8448 の値を直接入れたら合うのか試す
	// TODO エンコードした値から署名を検証するんじゃなくてデコード時にオリジナルの値を持っておくよう修正
	encryptedExtensionBytes, _ := hex.DecodeString("080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000")
	certificateBytes, _ := hex.DecodeString("0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000")
	certificateVerifyBytes, _ := hex.DecodeString("0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3")

	th := TranscriptHash(clientHello, serverHello,
		encryptedExtensionBytes, certificateBytes,
		certificateVerifyBytes)
	fmt.Printf("===== th ===== \n")
	printBytes(th)

	// th := TranscriptHash(clientHello, serverHello,
	// 	encryptedExtension.EncryptedExtensions.Encode(), certificate.Certificate.Encode(),
	// 	certificateVerify.Encode())

	hash.Write([]byte(th))

	// HMACを取得
	verifyData := hash.Sum(nil)
	fmt.Printf("===== hmac =====\n")
	printBytes(verifyData)

	fmt.Printf("REMAIN %+v\n", remain)

	t.Fail()

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
	// tag := aead.Seal(nil, nonce, cipherText, additionalData)

	// 認証タグを cipherText の末尾に追加する
	// cipherTextWithTag := append(cipherText, tag...)

	// 暗号文と認証タグから元のデータを復号化する
	plaintext, err := aead.Open(nil, nonce, cipherText, additionalData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
