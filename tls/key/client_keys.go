package key

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"

	"github.com/inabajunmr/ttllss/tls/handshake"
	"github.com/inabajunmr/ttllss/tls/record"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type ClientKeys struct {
	curve            elliptic.Curve
	clientPrivateKey []byte
	serverPublicKey  []byte
}

func (k *ClientKeys) SetCurve(curve elliptic.Curve) {
	k.curve = curve
}

func (k *ClientKeys) SetClientPrivateKey(privateKey []byte) {
	k.clientPrivateKey = privateKey
}

func (k *ClientKeys) SetServerPublicKey(publicKey []byte) {
	k.serverPublicKey = publicKey
}

// func (k ClientKeys) GetECDHESharedKey() []byte {
// 	x, _ := k.curve.ScalarMult(k.serverPubX, k.serverPubY, k.clientPrivateKey.D.Bytes())
// 	return x.Bytes()
// }

// 0
// |
// v
// PSK ->  HKDF-Extract = Early Secret
func (k ClientKeys) GetEarlySecret() []byte {
	hash := sha256.New
	return hkdf.Extract(hash, make([]byte, 32), []byte{})
}

// |
// +-----> Derive-Secret(., "ext binder" | "res binder", "")
// |                     = binder_key
// |
// +-----> Derive-Secret(., "c e traffic", ClientHello)
// |                     = client_early_traffic_secret
// |
// +-----> Derive-Secret(., "e exp master", ClientHello)
// |                     = early_exporter_master_secret
// v
// Derive-Secret(., "derived", "")
// |
// v
// (EC)DHE -> HKDF-Extract = Handshake Secret
func (k ClientKeys) GetHandshakeSecret() []byte {
	clientDeriveSecretForHandshake := DeriveSecret(k.GetEarlySecret(), []byte("derived"), []byte{})
	sharedKey, _ := curve25519.X25519(k.clientPrivateKey, k.serverPublicKey)
	return hkdf.Extract(sha256.New, sharedKey, clientDeriveSecretForHandshake)
}

// |
// +-----> Derive-Secret(., "c hs traffic",
// |                     ClientHello...ServerHello)
// |                     = client_handshake_traffic_secret
// |
// +-----> Derive-Secret(., "s hs traffic",
// |                     ClientHello...ServerHello)
// |                     = server_handshake_traffic_secret
func (k ClientKeys) GetServerHandshakeTrafficSecret(messages ...[]byte) []byte {
	return DeriveSecret(k.GetHandshakeSecret(), []byte("s hs traffic"), messages...)
}

func (k ClientKeys) GetFinishedKey(messages ...[]byte) []byte {
	return HkdfExpandLabel(k.GetServerHandshakeTrafficSecret(messages...), []byte("finished"), []byte(""), sha256.Size)
}

// TODO application trafic
// v
// Derive-Secret(., "derived", "")
// |
// v
// 0 -> HKDF-Extract = Master Secret
// |
// +-----> Derive-Secret(., "c ap traffic",
// |                     ClientHello...server Finished)
// |                     = client_application_traffic_secret_0
// |
// +-----> Derive-Secret(., "s ap traffic",
// |                     ClientHello...server Finished)
// |                     = server_application_traffic_secret_0
// |
// +-----> Derive-Secret(., "exp master",
// |                     ClientHello...server Finished)
// |                     = exporter_master_secret
// |
// +-----> Derive-Secret(., "res master",
// 					  ClientHello...client Finished)
// 					  = resumption_master_secret

func (k ClientKeys) DecryptTLSCiphertext(encrypted []byte, messages ...[]byte) []byte {

	serverHandshakeTrafficSecret := k.GetServerHandshakeTrafficSecret(messages...)

	encryptedCertificateMessage, _ := hex.DecodeString("17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b")
	_, certificateRecord := record.DecodeTLSCiphertext(encryptedCertificateMessage)
	fmt.Printf("certificateRecord.EncryptedRecord: %x\n", certificateRecord.EncryptedRecord)

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
		var secNumber uint64 = 0
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
		// writeIV https://datatracker.ietf.org/doc/html/rfc8446#section-7.3
		// [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
		serverWriteIV := HkdfExpandLabel(serverHandshakeTrafficSecret, []byte("iv"), []byte(""), uint16(ivLength))
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

	// AEAD Decrypt
	// https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
	// plaintext of encrypted_record =
	//      AEAD-Decrypt(peer_write_key, nonce,
	// 			 additional_data, AEADEncrypted)
	decrypted, err := decrypt(certificateRecord.EncryptedRecord, nonce, additionalData, serverWriteKey)
	if err != nil {
		log.Fatal(err)
	}
	return decrypted
}

func decrypt(cipherText, nonce, additionalData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, cipherText, additionalData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (k ClientKeys) Verify(f handshake.Finished, messages ...[]byte) bool {
	// client hello / server hello
	finishedKey := k.GetFinishedKey(messages[0], messages[1])
	// verify_data =
	// HMAC(finished_key,
	// 	 Transcript-Hash(Handshake Context,
	// 					 Certificate*, CertificateVerify*))

	hash := hmac.New(sha256.New, []byte(finishedKey))
	th := TranscriptHash(messages...)
	hash.Write([]byte(th))
	return reflect.DeepEqual(hash.Sum(nil), f.VerifyData)
}
