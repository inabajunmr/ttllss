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
	ClientHelloHandshakeType         HandshakeType = 1
	ServerHelloHandshakeType         HandshakeType = 2
	NewSessionTicketHandshakeType    HandshakeType = 4
	EndOfEarlyDataHandshakeType      HandshakeType = 5
	EncryptedExtensionsHandshakeType HandshakeType = 8
	CertificateHandshakeType         HandshakeType = 11
	CertificateRequestHandshakeType  HandshakeType = 13
	CertificateVerifyHandshakeType   HandshakeType = 15
	FinishedHandshakeType            HandshakeType = 20
	KeyUpdateHandshakeType           HandshakeType = 24
	MessageHashHandshakeType         HandshakeType = 254
	HandshakeType255HandshakeType    HandshakeType = 255
)

type HandshakeType byte

func (t HandshakeType) Encode() byte {
	return byte(t)
}

func DecodeHandshakeType(data []byte) ([]byte, HandshakeType) {
	t := data[0]
	return data[1:], HandshakeType(t)
}
