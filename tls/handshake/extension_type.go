package handshake

import (
	"bytes"
	"encoding/binary"
)

type ExtensionType uint16

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4.2

//	enum {
//		server_name(0),                             /* RFC 6066 */
//		max_fragment_length(1),                     /* RFC 6066 */
//		status_request(5),                          /* RFC 6066 */
//		supported_groups(10),                       /* RFC 8422, 7919 */
//		signature_algorithms(13),                   /* RFC 8446 */
//		use_srtp(14),                               /* RFC 5764 */
//		heartbeat(15),                              /* RFC 6520 */
//		application_layer_protocol_negotiation(16), /* RFC 7301 */
//		signed_certificate_timestamp(18),           /* RFC 6962 */
//		client_certificate_type(19),                /* RFC 7250 */
//		server_certificate_type(20),                /* RFC 7250 */
//		padding(21),                                /* RFC 7685 */
//		pre_shared_key(41),                         /* RFC 8446 */
//		early_data(42),                             /* RFC 8446 */
//		supported_versions(43),                     /* RFC 8446 */
//		cookie(44),                                 /* RFC 8446 */
//		psk_key_exchange_modes(45),                 /* RFC 8446 */
//		certificate_authorities(47),                /* RFC 8446 */
//		oid_filters(48),                            /* RFC 8446 */
//		post_handshake_auth(49),                    /* RFC 8446 */
//		signature_algorithms_cert(50),              /* RFC 8446 */
//		key_share(51),                              /* RFC 8446 */
//		(65535)
//	} ExtensionType;
const (
	ServerName                          ExtensionType = 0
	MaxFragmentLength                   ExtensionType = 1
	StatusRequest                       ExtensionType = 5
	SupportedGroups                     ExtensionType = 10
	SignatureAlgorithms                 ExtensionType = 13
	UseSRTP                             ExtensionType = 14
	Heartbeat                           ExtensionType = 15
	ApplicationLayerProtocolNegotiation ExtensionType = 16
	SignedCertificateTimestamp          ExtensionType = 18
	ClientCertificateType               ExtensionType = 19
	ServerCertificateType               ExtensionType = 20
	Padding                             ExtensionType = 21
	PreSharedKey                        ExtensionType = 41
	EarlyData                           ExtensionType = 42
	SupportedVersions                   ExtensionType = 43
	Cookie                              ExtensionType = 44
	PSKKeyExchangeModes                 ExtensionType = 45
	CertificateAuthorities              ExtensionType = 47
	OIDFilters                          ExtensionType = 48
	PostHandshakeAuth                   ExtensionType = 49
	SignatureAlgorithmsCert             ExtensionType = 50
	KeyShare                            ExtensionType = 51
)

func (e ExtensionType) Encode() []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(e))
	return bytes
}

func DecodeExtensionType(data []byte) ([]byte, ExtensionType) {
	extensionTypeByte := data[:2]
	var extensionType uint16
	binary.Read(bytes.NewReader(extensionTypeByte), binary.BigEndian, &extensionType)
	return data[2:], ExtensionType(extensionType)

}
