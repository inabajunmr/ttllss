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
	length      [3]byte
	clientHello ClientHello
	ServerHello ServerHello
	// end_of_early_data    EndOfEarlyData
	EncryptedExtensions EncryptedExtensions
	// certificate_request  CertificateRequest
	Certificate       Certificate
	CertificateVerify CertificateVerify
	Finished          Finished
	// new_session_ticke    NewSessionTicket
	// key_update           KeyUpdate
}

func NewHandshakeClientHello(msgType HandshakeType, clientHello ClientHello) Handshake {

	var length [3]byte
	// redundant
	clientHelloLength := len(clientHello.Encode())

	length[0] = byte(clientHelloLength >> 16 & 0xFF)
	length[1] = byte(clientHelloLength >> 8 & 0xFF)
	length[2] = byte(clientHelloLength & 0xFF)
	return Handshake{msgType: msgType, length: length, clientHello: clientHello}
}

func NewHandshakeServerHello(msgType HandshakeType, serverHello ServerHello) Handshake {

	var length [3]byte
	// redundant
	clientHelloLength := len(serverHello.Encode())

	length[0] = byte(clientHelloLength >> 16 & 0xFF)
	length[1] = byte(clientHelloLength >> 8 & 0xFF)
	length[2] = byte(clientHelloLength & 0xFF)
	return Handshake{msgType: msgType, length: length, ServerHello: serverHello}
}

func (h Handshake) Encode() []byte {
	encoded := []byte{}
	encoded = append(encoded, byte(h.msgType))

	encoded = append(encoded, h.length[:]...)

	var encodedMessage []byte
	switch h.msgType {
	case ClientHelloHandshakeType:
		encodedMessage = h.clientHello.Encode()
	case ServerHelloHandshakeType:
		encodedMessage = h.ServerHello.Encode()
	case EncryptedExtensionsHandshakeType:
		encodedMessage = h.EncryptedExtensions.Encode()
	case CertificateHandshakeType:
		encodedMessage = h.Certificate.Encode()
	case CertificateVerifyHandshakeType:
		encodedMessage = h.CertificateVerify.Encode()

	}
	encoded = append(encoded, encodedMessage...)

	return encoded
}

// msgType
func DecodeHandShake(data []byte) ([]byte, Handshake) {
	var msgType HandshakeType
	data, msgType = DecodeHandshakeType(data)

	// lenghth
	var length [3]byte
	copy(length[:], data[:3])
	lengthInt := int(length[0])<<16 | int(length[1])<<8 | int(length[2])

	data = data[3:]

	// handshake message
	payload := data[:lengthInt]
	remain := data[lengthInt:]

	switch msgType {
	case ClientHelloHandshakeType:
		return remain, Handshake{
			msgType:     msgType,
			length:      length,
			clientHello: DecodeClientHello(payload),
		}
	case ServerHelloHandshakeType:
		DecodeServerHello(payload)
		return remain, Handshake{
			msgType:     msgType,
			length:      length,
			ServerHello: DecodeServerHello(payload),
		}

	case EncryptedExtensionsHandshakeType:
		return remain, Handshake{
			msgType:             msgType,
			length:              length,
			EncryptedExtensions: DecodeEncryptedExtensions(payload),
		}
	case CertificateHandshakeType:
		return remain, Handshake{
			msgType:     msgType,
			length:      length,
			Certificate: DecodeCertificate(payload),
		}
	case CertificateVerifyHandshakeType:
		return remain, Handshake{
			msgType:           msgType,
			length:            length,
			CertificateVerify: DecodeCertificateVerify(payload),
		}
	case FinishedHandshakeType:
		return remain, Handshake{
			msgType:  msgType,
			length:   length,
			Finished: DecodeFinished(payload),
		}
	}

	// TODO exception
	return remain, Handshake{
		msgType: msgType,
		length:  length,
	}

}
