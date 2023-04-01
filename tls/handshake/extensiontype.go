package handshake

import "encoding/binary"

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
	serverName                          ExtensionType = 0
	maxFragmentLength                                 = 1
	statusRequest                                     = 5
	supportedGroups                                   = 10
	signatureAlgorithms                               = 13
	useSRTP                                           = 14
	heartbeat                                         = 15
	applicationLayerProtocolNegotiation               = 16
	signedCertificateTimestamp                        = 18
	clientCertificateType                             = 19
	serverCertificateType                             = 20
	padding                                           = 21
	preSharedKey                                      = 41
	earlyData                                         = 42
	supportedVersions                                 = 43
	cookie                                            = 44
	pskKeyExchangeModes                               = 45
	certificateAuthorities                            = 47
	oidFilters                                        = 48
	postHandshakeAuth                                 = 49
	signatureAlgorithmsCert                           = 50
	keyShare                                          = 51
)

func (e ExtensionType) Encode() []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(e))
	return bytes
}
