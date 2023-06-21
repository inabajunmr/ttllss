package key

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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

func (k ClientKeys) DecryptTLSCiphertext(encrypted record.TLSCiphertext, messages ...[]byte) []byte {

	serverHandshakeTrafficSecret := k.GetServerHandshakeTrafficSecret(messages...)

	// AdditionalData
	var additionalData []byte
	{
		additionalData = encrypted.AdditionalData()
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
	decrypted, err := decrypt(encrypted.EncryptedRecord, nonce, additionalData, serverWriteKey)
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
