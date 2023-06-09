package key

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/inabajunmr/ttllss/tls/handshake"
	"github.com/inabajunmr/ttllss/tls/record"
	"golang.org/x/crypto/curve25519"
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
	keys.SetClientPrivateKey(clientPrivateKey)

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
	keys.SetServerPublicKey(serverPublicKey)
	fmt.Printf("serverPublicKey: %x\n", serverPublicKey)

	// {client}  derive secret "tls13 c hs traffic" (same as server)

	encryptedCertificateMessage, _ := hex.DecodeString("17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b")
	_, certificateRecord := record.DecodeTLSCiphertext(encryptedCertificateMessage)
	fmt.Printf("certificateRecord.EncryptedRecord: %x\n", certificateRecord.EncryptedRecord)

	// AEAD Decrypt
	decrypted := keys.DecryptTLSCiphertext(certificateRecord, clientHello, serverHello)
	fmt.Println("decrypted")
	printBytes(decrypted)
	remain, encryptedExtension := handshake.DecodeHandShake(decrypted)
	fmt.Printf("===== encryptedExtension ===== \n %+v\n", encryptedExtension)
	remain, certificate := handshake.DecodeHandShake(remain)
	fmt.Printf("===== certificate ===== \n %+v\n", certificate)
	// 証明書検証は多分サンプルなので無理
	// 最初の方に証明書の秘密鍵書いてあった
	remain, certificateVerify := handshake.DecodeHandShake(remain)
	fmt.Printf("===== certificateVerify ===== \n %+v\n", certificateVerify)
	_, finished := handshake.DecodeHandShake(remain)

	// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
	// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
	// base key is serverHandshakeTrafficSecret at https://datatracker.ietf.org/doc/html/rfc8446#section-4.4

	if !keys.Verify(finished.Finished, clientHello, serverHello,
		encryptedExtension.OriginalPayload, certificate.OriginalPayload,
		certificateVerify.OriginalPayload) {
		t.Fatal("Failed to Finished message verification")
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
