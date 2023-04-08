package handshake

import (
	"bytes"
	"encoding/binary"
)

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3

// enum {
// 	/* RSASSA-PKCS1-v1_5 algorithms */
// 	rsa_pkcs1_sha256(0x0401),
// 	rsa_pkcs1_sha384(0x0501),
// 	rsa_pkcs1_sha512(0x0601),

// 	/* ECDSA algorithms */
// 	ecdsa_secp256r1_sha256(0x0403),
// 	ecdsa_secp384r1_sha384(0x0503),
// 	ecdsa_secp521r1_sha512(0x0603),

// 	/* RSASSA-PSS algorithms with public key OID rsaEncryption */
// 	rsa_pss_rsae_sha256(0x0804),
// 	rsa_pss_rsae_sha384(0x0805),
// 	rsa_pss_rsae_sha512(0x0806),

// 	/* EdDSA algorithms */
// 	ed25519(0x0807),
// 	ed448(0x0808),

// 	/* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
// 	rsa_pss_pss_sha256(0x0809),
// 	rsa_pss_pss_sha384(0x080a),
// 	rsa_pss_pss_sha512(0x080b),

// 	/* Legacy algorithms */
// 	rsa_pkcs1_sha1(0x0201),
// 	ecdsa_sha1(0x0203),

// 	/* Reserved Code Points */
// 	private_use(0xFE00..0xFFFF),
// 	(0xFFFF)
// } SignatureScheme;

const (
	// RSASSA-PKCS1-v1_5 algorithms
	RsaPkcs1Sha256 SignatureScheme = 0x0401
	RsaPkcs1Sha384                 = 0x0501
	RsaPkcs1Sha512                 = 0x0601
	// ECDSA algorithms
	EcdsaSecp256r1Sha256    = 0x0403
	EcdsaSecp384r1Sha384    = 0x0503
	EcdsaSecp521r1Sha512    = 0x0603
	RsaPssRsaESha256        = 0x0804
	RsaPssRsaESha384        = 0x0805
	RsaPssRsaESha512        = 0x0806
	Ed25519                 = 0x0807
	Ed448                   = 0x0808
	RsaPssPssSha256         = 0x0809
	RsaPssPssSha384         = 0x080a
	RsaPssPssSha512         = 0x080b
	RsaPkcs1Sha1            = 0x0201
	EcdsaSha1               = 0x0203
	PrivateUse              = 0xFE00
	ReservedCodePointsStart = 0xFE00
	ReservedCodePointsEnd   = 0xFFFF
)

type SignatureScheme uint16

func (p SignatureScheme) Encode() []byte {
	versionByte := make([]byte, 2)
	binary.BigEndian.PutUint16(versionByte, uint16(p))
	return versionByte
}

func DecodeSignatureScheme(b []byte) ([]byte, SignatureScheme) {
	schemeBytes := b[:2]
	var scheme SignatureScheme
	binary.Read(bytes.NewReader(schemeBytes), binary.BigEndian, &scheme)
	return b[2:], scheme
}
