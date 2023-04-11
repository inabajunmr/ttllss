package handshake

// ref. https://datatracker.ietf.org/doc/html/rfc8446#section-4

// struct {
// 	HandshakeType msg_type;    /* handshake type */
// 	uint24 length;             /* remaining bytes in message */
// 	select (Handshake.msg_type) {
// 		case client_hello:          ClientHello;
// 		case server_hello:          ServerHello;
// 		case end_of_early_data:     EndOfEarlyData;
// 		case encrypted_extensions:  EncryptedExtensions;
// 		case certificate_request:   CertificateRequest;
// 		case certificate:           Certificate;
// 		case certificate_verify:    CertificateVerify;
// 		case finished:              Finished;
// 		case new_session_ticket:    NewSessionTicket;
// 		case key_update:            KeyUpdate;
// 	};
// } Handshake;

type Handshake struct {
	msgType     HandshakeType
	length      [3]byte // TODO length いらなさそう
	clientHello ClientHello
	// server_hello         ServerHello
	// end_of_early_data    EndOfEarlyData
	// encrypted_extensions EncryptedExtensions
	// certificate_request  CertificateRequest
	// certificate          Certificate
	// certificate_verify   CertificateVerify
	// finished             Finished
	// new_session_ticke    NewSessionTicket
	// key_update           KeyUpdate
}

func NewHandshakeClientHello(msgType HandshakeType, length [3]byte, clientHello ClientHello) Handshake {
	// num := len(clientHello.Encode())
	// var buf [3]byte
	// binary.BigEndian.PutUint32(buf[:], uint32(num))
	return Handshake{msgType: msgType, length: length, clientHello: clientHello}
}

func (h Handshake) Encode() []byte {
	encoded := []byte{}
	encoded = append(encoded, byte(h.msgType))

	encoded = append(encoded, h.length[:]...)

	encodedClientHello := h.clientHello.Encode()
	encoded = append(encoded, encodedClientHello...)

	return encoded

}
