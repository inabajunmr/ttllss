package handshake

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4

// enum {
// 	client_hello(1),
// 	server_hello(2),
// 	new_session_ticket(4),
// 	end_of_early_data(5),
// 	encrypted_extensions(8),
// 	certificate(11),
// 	certificate_request(13),
// 	certificate_verify(15),
// 	finished(20),
// 	key_update(24),
// 	message_hash(254),
// 	(255)
// } HandshakeType;

const (
	ClientHelloType         HandshakeType = 1
	ServerHelloType         HandshakeType = 2
	NewSessionTicketType    HandshakeType = 4
	EndOfEarlyDataType      HandshakeType = 5
	EncryptedExtensionsType HandshakeType = 8
	CertificateType         HandshakeType = 11
	CertificateRequestType  HandshakeType = 13
	CertificateVerifyType   HandshakeType = 15
	FinishedType            HandshakeType = 20
	KeyUpdateType           HandshakeType = 24
	MessageHashType         HandshakeType = 254
	HandshakeType255Type    HandshakeType = 255
)

type HandshakeType byte

func (t HandshakeType) Encode() byte {
	return byte(t)
}

func DecodeHandshakeType(data []byte) ([]byte, HandshakeType) {
	t := data[0]
	return data[1:], HandshakeType(t)
}
